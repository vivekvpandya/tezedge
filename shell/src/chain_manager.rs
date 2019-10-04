// Copyright (c) SimpleStaking and Tezos-RS Contributors
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use failure::Error;
use itertools::Itertools;
use log::{debug, info, trace, warn};
use riker::actors::*;

use networking::p2p::binary_message::MessageHash;
use networking::p2p::encoding::prelude::*;
use networking::p2p::network_channel::{NetworkChannelMsg, NetworkChannelRef};
use networking::p2p::peer::{PeerRef, SendMessage};
use storage::{BlockHeaderWithHash, BlockStorage, BlockStorageReader, OperationsStorage, OperationsStorageReader, StorageError};
use tezos_client::client::TezosStorageInitInfo;
use tezos_encoding::hash::{BlockHash, ChainId, HashEncoding, HashType};

use crate::{subscribe_to_actor_terminated, subscribe_to_network_events, subscribe_to_shell_events};
use crate::block_state::{BlockState, MissingBlock};
use crate::operations_state::{MissingOperations, OperationsState};
use crate::shell_channel::{AllBlockOperationsReceived, BlockReceived, ShellChannelMsg, ShellChannelRef, ShellChannelTopic};

const BLOCK_HEADERS_BATCH_SIZE: usize = 10;
const OPERATIONS_BATCH_SIZE: usize = 10;
const PEER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
const PEER_SILENCE_TIMEOUT: Duration = Duration::from_secs(120);
const CHECK_CHAIN_COMPLETENESS_INTERVAL: Duration = Duration::from_secs(30);
const ASK_CURRENT_BRANCH_INTERVAL: Duration = Duration::from_secs(50);

#[derive(Clone, Debug)]
pub struct CheckChainCompleteness;

#[derive(Clone, Debug)]
pub struct AskPeersAboutCurrentBranch;

#[derive(Clone, Debug)]
pub struct DisconnectSilentPeers;


/// This struct holds info about local and remote "current" head
#[derive(Clone, Debug)]
struct CurrentHead {
    /// Represents local current head. Value here is teh same as the
    /// hast of the lst applied block.
    local: BlockHash,
    /// Remote / network remote current head. This represents info about
    /// the current branch with the highest level received from network.
    remote: BlockHash,
    /// Level of the remote current head.
    remote_level: i32,
}

#[actor(CheckChainCompleteness, AskPeersAboutCurrentBranch, DisconnectSilentPeers, NetworkChannelMsg, ShellChannelMsg, SystemEvent)]
pub struct ChainManager {
    /// All events generated by the network layer will end up in this channel
    network_channel: NetworkChannelRef,
    /// All events from shell will be published to this channel
    shell_channel: ShellChannelRef,
    /// Holds the state of all peers
    peers: HashMap<ActorUri, PeerState>,
    /// Block storage
    block_storage: Box<dyn BlockStorageReader>,
    /// Operations storage
    operations_storage: Box<dyn OperationsStorageReader>,
    /// Holds state of the block chain
    block_state: BlockState,
    /// Holds state of the operations
    operations_state: OperationsState,
    /// Current head information
    current_head: CurrentHead
}

pub type ChainManagerRef = ActorRef<ChainManagerMsg>;

impl ChainManager {

    pub fn actor(sys: &impl ActorRefFactory, network_channel: NetworkChannelRef, shell_channel: ShellChannelRef, rocks_db: Arc<rocksdb::DB>, init_info: &TezosStorageInitInfo) -> Result<ChainManagerRef, CreateError> {
        sys.actor_of(
            Props::new_args(ChainManager::new, (network_channel, shell_channel, rocks_db, init_info.chain_id.clone(),
                                                CurrentHead { local: init_info.current_block_header_hash.clone(), remote: init_info.genesis_block_header_hash.clone(), remote_level: 0 })),
            ChainManager::name())
    }

    /// The `ChainManager` is intended to serve as a singleton actor so that's why
    /// we won't support multiple names per instance.
    fn name() -> &'static str {
        "chain-manager"
    }

    fn new((network_channel, shell_channel, rocks_db, chain_id, current_head): (NetworkChannelRef, ShellChannelRef, Arc<rocksdb::DB>, ChainId, CurrentHead)) -> Self {
        assert!(PEER_SILENCE_TIMEOUT > ASK_CURRENT_BRANCH_INTERVAL * 2);
        ChainManager {
            network_channel,
            shell_channel,
            block_storage: Box::new(BlockStorage::new(rocks_db.clone())),
            operations_storage: Box::new(OperationsStorage::new(rocks_db.clone())),
            block_state: BlockState::new(rocks_db.clone(), rocks_db.clone(), &chain_id),
            operations_state: OperationsState::new(rocks_db.clone(), rocks_db),
            peers: HashMap::new(),
            current_head,
        }
    }

    fn check_chain_completeness(&mut self) -> Result<(), Error> {
        let ChainManager { peers, block_state, operations_state, .. } = self;

        if block_state.has_missing_blocks() {
            peers.values_mut()
                .sorted_by_key(|peer| peer.available_block_queue_capacity()).rev()
                .for_each(|peer| {
                    let available_capacity = peer.available_block_queue_capacity();
                    if available_capacity > 0 {
                        let mut missing_blocks = block_state.drain_missing_blocks(available_capacity);
                        if !missing_blocks.is_empty() {

                            let queued_blocks = missing_blocks.drain(..)
                                .map(|missing_block| {
                                    let missing_block_hash = missing_block.block_hash.clone();
                                    if let None = peer.queued_block_headers.insert(missing_block_hash.clone(), missing_block) {
                                        // block was not already present in queue
                                        Some(missing_block_hash)
                                    } else {
                                        // block was already in queue
                                        None
                                    }
                                })
                                .filter_map(|missing_block_hash| missing_block_hash)
                                .collect::<Vec<_>>();

                            if !queued_blocks.is_empty() {
                                tell_peer(GetBlockHeadersMessage::new(queued_blocks).into(), peer);
                            }
                        }
                    }
                });
        }

        if operations_state.has_missing_operations() {
            peers.values_mut()
                .sorted_by_key(|peer| peer.available_operations_queue_capacity()).rev()
                .for_each(|peer| {
                    let available_capacity = peer.available_operations_queue_capacity();
                    if available_capacity > 0 {
                        let missing_operations = operations_state.drain_missing_operations(available_capacity);
                        if !missing_operations.is_empty() {

                            let queued_operations = missing_operations.iter()
                                .map(|missing_operation| {
                                    if let None = peer.queued_operations.insert(missing_operation.block_hash.clone(), missing_operation.clone()) {
                                        // operations were not already present in queue
                                        Some(missing_operation)
                                    } else {
                                        // operations were already in queue
                                        None
                                    }
                                })
                                .filter_map(|missing_operation| missing_operation)
                                .collect::<Vec<_>>();

                            queued_operations.iter()
                                .for_each(|&missing_operation| tell_peer(GetOperationsForBlocksMessage::new(missing_operation.into()).into(), peer));
                        }
                    }
                });
        }

        Ok(())
    }

    fn process_network_channel_message(&mut self, ctx: &Context<ChainManagerMsg>, msg: NetworkChannelMsg) -> Result<(), Error> {
        let ChainManager {
            peers,
            block_state,
            operations_state,
            shell_channel,
            block_storage,
            operations_storage,
            ..
        } = self;

        match msg {
            NetworkChannelMsg::PeerBootstrapped(msg) => {
                debug!("Requesting current branch from peer: {}", &msg.peer);
                let peer = PeerState::new(msg.peer);
                // store peer
                let actor_uri = peer.peer_ref.uri().clone();
                self.peers.insert(actor_uri.clone(), peer);

                let peer = self.peers.get_mut(&actor_uri).unwrap();
                tell_peer(GetCurrentBranchMessage::new(block_state.get_chain_id().clone()).into(), peer);
            }
            NetworkChannelMsg::PeerMessageReceived(received) => {
                match peers.get_mut(received.peer.uri()) {
                    Some(peer) => {
                        peer.response_last = Instant::now();

                        for message in &received.message.messages {
                            match message {
                                PeerMessage::CurrentBranch(message) => {
                                    debug!("Received current branch from peer: {}", &received.peer);
                                    message.current_branch().history.iter().cloned().rev()
                                        .map(|history_block_hash| block_state.push_missing_block(history_block_hash.into()))
                                        .collect::<Result<Vec<_>, _>>()?;

                                    let current_head = &message.current_branch().current_head;

                                    // if needed, update remote current head
                                    if message.current_branch().current_head.level() > self.current_head.remote_level {
                                        self.current_head.remote_level = message.current_branch().current_head.level();
                                        self.current_head.remote = message.current_branch().current_head.message_hash()?;
                                    }

                                    // notify others that new block was received
                                    shell_channel.tell(
                                        Publish {
                                            msg: BlockReceived {
                                                hash: current_head.message_hash()?,
                                                level: current_head.level(),
                                            }.into(),
                                            topic: ShellChannelTopic::ShellEvents.into(),
                                        }, Some(ctx.myself().into()));

                                    // trigger CheckChainCompleteness
                                    ctx.myself().tell(CheckChainCompleteness, None);
                                }
                                PeerMessage::GetCurrentBranch(message) => {
                                    debug!("Current branch requested by peer: {}", &received.peer);
                                    if block_state.get_chain_id() == &message.chain_id {
                                        if let Some(current_head) = block_storage.get(&self.current_head.local)? {
                                            let msg = CurrentBranchMessage::new(block_state.get_chain_id().clone(), CurrentBranch::new(&current_head.header));
                                            tell_peer(msg.into(), peer);
                                        }
                                    }
                                }
                                PeerMessage::BlockHeader(message) => {
                                    let block_header_with_hash = BlockHeaderWithHash::new(message.block_header().clone()).unwrap();
                                    match peer.queued_block_headers.remove(&block_header_with_hash.hash) {
                                        Some(missing_block) => {
                                            debug!("Received block header from peer: {}", &received.peer);
                                            let is_new_block =
                                                block_state.process_block_header(&block_header_with_hash)
                                                    .and(operations_state.process_block_header(&block_header_with_hash))?;

                                            if is_new_block {
                                                // trigger CheckChainCompleteness
                                                ctx.myself().tell(CheckChainCompleteness, None);

                                                // notify others that new block was received
                                                shell_channel.tell(
                                                    Publish {
                                                        msg: BlockReceived {
                                                            hash: missing_block.block_hash,
                                                            level: missing_block.level,
                                                        }.into(),
                                                        topic: ShellChannelTopic::ShellEvents.into(),
                                                    }, Some(ctx.myself().into()));
                                            }
                                        }
                                        None => {
                                            warn!("Received unexpected block header {} from peer: {}", HashEncoding::new(HashType::BlockHash).bytes_to_string(&block_header_with_hash.hash), &received.peer);
                                            ctx.system.stop(received.peer.clone());
                                        }
                                    }
                                }
                                PeerMessage::GetBlockHeaders(message) => {
                                    for block_hash in message.get_block_headers() {
                                        if let Some(block) = block_storage.get(block_hash)? {
                                            let msg: BlockHeaderMessage = (*block.header).clone().into();
                                            tell_peer(msg.into(), peer);
                                        }
                                    }
                                },
                                PeerMessage::GetCurrentHead(message) => {
                                    debug!("Current head requested by peer: {}", &received.peer);
                                    if block_state.get_chain_id() == message.chain_id() {
                                        if let Some(current_head) = block_storage.get(&self.current_head.local)? {
                                            let msg = CurrentHeadMessage::new(block_state.get_chain_id().clone(), (*current_head.header).clone());
                                            tell_peer(msg.into(), peer);
                                        }
                                    }
                                }
                                PeerMessage::OperationsForBlocks(operations) => {
                                    let block_hash = operations.operations_for_block.hash.clone();
                                    match peer.queued_operations.get_mut(&block_hash) {
                                        Some(missing_operations) => {
                                            let operation_was_expected = missing_operations.validation_passes.remove(&operations.operations_for_block.validation_pass);
                                            if operation_was_expected {
                                                debug!("Received operations validation pass #{} from peer: {}", operations.operations_for_block.validation_pass, &received.peer);
                                                if operations_state.process_block_operations(&operations)? {
                                                    // trigger CheckChainCompleteness
                                                    ctx.myself().tell(CheckChainCompleteness, None);

                                                    // notify others that new all operations for block were received
                                                    let block = block_storage.get(&block_hash)?.ok_or(StorageError::MissingKey)?;
                                                    shell_channel.tell(
                                                        Publish {
                                                            msg: AllBlockOperationsReceived {
                                                                hash: block.hash,
                                                                level: block.header.level()
                                                            }.into(),
                                                            topic: ShellChannelTopic::ShellEvents.into(),
                                                        }, Some(ctx.myself().into()));

                                                    // remove operations from queue
                                                    peer.queued_operations.remove(&block_hash);
                                                }
                                            } else {
                                                warn!("Received unexpected validation pass #{} from peer: {}", operations.operations_for_block.validation_pass, &received.peer);
                                                ctx.system.stop(received.peer.clone());
                                            }
                                        }
                                        None => {
                                            warn!("Received unexpected operations from peer: {}", &received.peer);
                                            ctx.system.stop(received.peer.clone());
                                        }
                                    }
                                }
                                PeerMessage::GetOperationsForBlocks(message) => {
                                    for get_op in &message.get_operations_for_blocks {
                                        if get_op.validation_pass < 0 {
                                            continue
                                        }

                                        let key = get_op.into();
                                        if let Some(op) = operations_storage.get(&key)? {
                                            tell_peer(op.into(), peer);
                                        }
                                    }
                                }
                                _ => trace!("Ignored message: {:?}", message)
                            }
                        }
                    }
                    None => debug!("Received message from non-existing peer: {}", &received.peer)
                }
            }
            _ => (),
        }

        Ok(())
    }

    fn disconnect_silent_peers(&mut self, ctx: &Context<ChainManagerMsg>) {
        &self.peers.values()
            .for_each(|peer_state| {
                let response_duration = if peer_state.request_last > peer_state.response_last {
                    peer_state.request_last - peer_state.response_last
                } else {
                    Duration::from_secs(0)
                };

                if response_duration > PEER_RESPONSE_TIMEOUT {
                    info!("Timeout when waiting for response from peer {:?}. Disconnecting peer.", &peer_state.peer_ref);
                    ctx.system.stop(peer_state.peer_ref.clone());
                }

                let request_silence = Instant::now() - peer_state.response_last;
                if request_silence > PEER_SILENCE_TIMEOUT {
                    info!("Disconnecting silent peer {:?}.", &peer_state.peer_ref);
                    ctx.system.stop(peer_state.peer_ref.clone());
                }
            });
    }

    fn process_shell_channel_message(&mut self, _ctx: &Context<ChainManagerMsg>, msg: ShellChannelMsg) -> Result<(), Error> {
        match msg {
            ShellChannelMsg::BlockApplied(message) => {
                self.current_head.local = message.hash;
            }
            _ => ()
        }

        Ok(())
    }
}

impl Actor for ChainManager {
    type Msg = ChainManagerMsg;

    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        subscribe_to_actor_terminated(ctx.system.sys_events(), ctx.myself());
        subscribe_to_network_events(&self.network_channel, ctx.myself());
        subscribe_to_shell_events(&self.shell_channel, ctx.myself());

        info!("Hydrating block state");
        self.block_state.hydrate().expect("Failed to hydrate block state");
        info!("Hydrating operations state");
        self.operations_state.hydrate().expect("Failed to hydrate operations state");
        info!("Hydrating completed successfully");

        ctx.schedule::<Self::Msg, _>(
            CHECK_CHAIN_COMPLETENESS_INTERVAL / 4,
            CHECK_CHAIN_COMPLETENESS_INTERVAL.clone(),
            ctx.myself(),
            None,
            CheckChainCompleteness.into());

        ctx.schedule::<Self::Msg, _>(
            PEER_RESPONSE_TIMEOUT.clone(),
            PEER_RESPONSE_TIMEOUT / 2,
            ctx.myself(),
            None,
            DisconnectSilentPeers.into());

        ctx.schedule::<Self::Msg, _>(
            ASK_CURRENT_BRANCH_INTERVAL.clone(),
            ASK_CURRENT_BRANCH_INTERVAL.clone(),
            ctx.myself(),
            None,
            AskPeersAboutCurrentBranch.into());
    }

    fn sys_recv(&mut self, ctx: &Context<Self::Msg>, msg: SystemMsg, sender: Option<BasicActorRef>) {
        if let SystemMsg::Event(evt) = msg {
            self.receive(ctx, evt, sender);
        }
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<SystemEvent> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: SystemEvent, _sender: Option<BasicActorRef>) {
        if let SystemEvent::ActorTerminated(evt) = msg {
            if let Some(mut peer) = self.peers.remove(evt.actor.uri()) {
                peer.queued_block_headers
                    .drain()
                    .for_each(|(_, missing_block)| {
                        self.block_state.push_missing_block(missing_block).expect("Failed to re-schedule block hash");
                    });

                self.operations_state.push_missing_operations(peer.queued_operations.drain().map(|(_, op)| op))
                    .expect("Failed to return to queue")
            }
        }
    }
}

impl Receive<CheckChainCompleteness> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, _msg: CheckChainCompleteness, _sender: Sender) {
        match self.check_chain_completeness() {
            Ok(_) => (),
            Err(e) => warn!("Failed to check chain completeness: {:?}", e),
        }
    }
}
impl Receive<DisconnectSilentPeers> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, _msg: DisconnectSilentPeers, _sender: Sender) {
        self.disconnect_silent_peers(ctx)
    }
}


impl Receive<NetworkChannelMsg> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: NetworkChannelMsg, _sender: Sender) {
        match self.process_network_channel_message(ctx, msg) {
            Ok(_) => (),
            Err(e) => warn!("Failed to process network channel message: {:?}", e),
        }
    }
}

impl Receive<ShellChannelMsg> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: ShellChannelMsg, _sender: Sender) {
        match self.process_shell_channel_message(ctx, msg) {
            Ok(_) => (),
            Err(e) => warn!("Failed to process shell channel message: {:?}", e),
        }
    }
}

impl Receive<AskPeersAboutCurrentBranch> for ChainManager {
    type Msg = ChainManagerMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, _msg: AskPeersAboutCurrentBranch, _sender: Sender) {
        let ChainManager { peers, block_state, .. } = self;
        peers.iter_mut()
            .for_each(|(_, peer)| tell_peer(GetCurrentBranchMessage::new(block_state.get_chain_id().clone()).into(), peer))
    }
}

struct PeerState {
    peer_ref: PeerRef,
    queued_block_headers: HashMap<BlockHash, MissingBlock>,
    queued_operations: HashMap<BlockHash, MissingOperations>,
    request_last: Instant,
    response_last: Instant,
}

impl PeerState {
    fn new(peer_ref: PeerRef) -> Self {
        PeerState {
            peer_ref,
            queued_block_headers: HashMap::new(),
            queued_operations: HashMap::new(),
            request_last: Instant::now(),
            response_last: Instant::now(),
        }
    }

    fn available_block_queue_capacity(&self) -> usize {
        let queued_count = self.queued_block_headers.len();
        if queued_count < BLOCK_HEADERS_BATCH_SIZE {
            BLOCK_HEADERS_BATCH_SIZE - queued_count
        } else {
            0
        }
    }

    fn available_operations_queue_capacity(&self) -> usize {
        let queued_count = self.queued_operations.len();
        if queued_count < OPERATIONS_BATCH_SIZE {
            OPERATIONS_BATCH_SIZE - queued_count
        } else {
            0
        }
    }
}

fn tell_peer(msg: PeerMessageResponse, peer: &mut PeerState) {
    peer.peer_ref.tell(SendMessage::new(msg), None);
    peer.request_last = Instant::now();
}