// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use std::sync::Once;

use ocaml_interop::{FromOCaml, OCaml, OCamlFn1, OCamlRuntime, ToOCaml, ToRust, ocaml_call, ocaml_frame, to_ocaml};

use tezos_api::ffi::*;
use tezos_api::ocaml_conv::FfiPath;

use crate::runtime;
use crate::runtime::OcamlError;

mod tezos_ffi {
    use ocaml_interop::{ocaml, OCamlBytes, OCamlInt, OCamlInt32, OCamlList};

    use tezos_api::{
        ffi::{
            ApplyBlockRequest, ApplyBlockResponse, BeginApplicationRequest,
            BeginApplicationResponse, BeginConstructionRequest, HelpersPreapplyResponse,
            PrevalidatorWrapper, ProtocolRpcError, ProtocolRpcRequest, ProtocolRpcResponse,
            ValidateOperationRequest, ValidateOperationResponse,
        },
        ocaml_conv::{OCamlOperationHash, OCamlProtocolHash},
    };
    use tezos_messages::p2p::encoding::operations_for_blocks::Path;

    ocaml! {
        pub fn apply_block(apply_block_request: ApplyBlockRequest) -> ApplyBlockResponse;
        pub fn begin_application(begin_application_request: BeginApplicationRequest) -> BeginApplicationResponse;
        pub fn begin_construction(begin_construction_request: BeginConstructionRequest) -> PrevalidatorWrapper;
        pub fn validate_operation(validate_operation_request: ValidateOperationRequest) -> ValidateOperationResponse;
        pub fn call_protocol_rpc(request: ProtocolRpcRequest) -> Result<ProtocolRpcResponse, ProtocolRpcError>;
        pub fn helpers_preapply_operations(request: ProtocolRpcRequest) -> HelpersPreapplyResponse;
        pub fn helpers_preapply_block(request: ProtocolRpcRequest) -> HelpersPreapplyResponse;
        pub fn change_runtime_configuration(
            log_enabled: bool,
            no_of_ffi_calls_treshold_for_gc: OCamlInt,
            debug_mode: bool
        );
        pub fn init_protocol_context(
            data_dir: String,
            genesis: (OCamlBytes, OCamlBytes, OCamlBytes),
            protocol_override: (OCamlList<(OCamlInt32, OCamlBytes)>,
                                OCamlList<(OCamlBytes, OCamlBytes)>),
            configuration: (bool, bool, bool),
            sandbox_json_patch_context: Option<(OCamlBytes, OCamlBytes)>
        ) -> (OCamlList<OCamlBytes>, Option<OCamlBytes>);
        pub fn genesis_result_data(
            context_hash: OCamlBytes,
            chain_id: OCamlBytes,
            protocol_hash: OCamlBytes,
            genesis_max_operations_ttl: OCamlInt
        ) -> (OCamlBytes, OCamlBytes, OCamlBytes);
        pub fn decode_context_data(
            protocol_hash: OCamlBytes,
            key: OCamlList<OCamlBytes>,
            data: OCamlBytes
        ) -> Option<OCamlBytes>;
        pub fn compute_path(request: OCamlList<OCamlList<OCamlOperationHash>>) -> OCamlList<Path>;
        pub fn assert_encoding_for_protocol_data(protocol_hash: OCamlProtocolHash, protocol_data: OCamlBytes);
    }
}

/// Initializes the ocaml runtime and the tezos-ffi callback mechanism.
pub fn setup() -> OCamlRuntime {
    static INIT: Once = Once::new();
    let ocaml_runtime = OCamlRuntime::init();

    INIT.call_once(|| {
        tezos_interop_callback::initialize_callbacks();
    });

    ocaml_runtime
}

/// Tries to shutdown ocaml runtime gracefully - give chance to close resources, trigger GC finalization...
///
/// https://caml.inria.fr/pub/docs/manual-ocaml/intfc.html#sec467
pub fn shutdown() {
    // TODO
    //ocaml_interop::OCamlRuntime::shutdown_persistent()
}

pub fn change_runtime_configuration(
    settings: TezosRuntimeConfiguration,
) -> Result<Result<(), TezosRuntimeConfigurationError>, OcamlError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        let result = ocaml_call!(tezos_ffi::change_runtime_configuration(
            rt,
            OCaml::of_bool(settings.log_enabled),
            OCaml::of_i32(settings.no_of_ffi_calls_treshold_for_gc),
            OCaml::of_bool(settings.debug_mode)
        ));
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(TezosRuntimeConfigurationError::from(e)),
        }
    })
}

pub fn init_protocol_context(
    storage_data_dir: String,
    genesis: GenesisChain,
    protocol_overrides: ProtocolOverrides,
    commit_genesis: bool,
    enable_testchain: bool,
    readonly: bool,
    patch_context: Option<PatchContext>,
) -> Result<Result<InitProtocolContextResult, TezosStorageInitError>, OcamlError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(rt,
            (
                genesis_tuple,
                protocol_overrides_tuple,
                configuration,
                patch_context_tuple
            ),
            {
                // genesis configuration
                let genesis_tuple = to_ocaml!(
                    rt,
                    (genesis.time, genesis.block, genesis.protocol),
                    genesis_tuple
                );

                // protocol overrides
                let protocol_overrides_tuple = to_ocaml!(
                    rt,
                    (
                        protocol_overrides.forced_protocol_upgrades,
                        protocol_overrides.voted_protocol_overrides,
                    ),
                    protocol_overrides_tuple
                );

                // configuration
                let configuration = to_ocaml!(
                    rt,
                    (commit_genesis, enable_testchain, readonly),
                    configuration
                );

                // patch context
                let patch_context_tuple = to_ocaml!(
                    rt,
                    patch_context.map(|pc| (pc.key, pc.json)),
                    patch_context_tuple
                );

                let storage_data_dir = to_ocaml!(rt, storage_data_dir);
                let result = ocaml_call!(tezos_ffi::init_protocol_context(
                    rt,
                    storage_data_dir,
                    rt.get(&genesis_tuple),
                    rt.get(&protocol_overrides_tuple),
                    rt.get(&configuration),
                    rt.get(&patch_context_tuple)
                ));

                match result {
                    Ok(result) => {
                        let (supported_protocol_hashes, genesis_commit_hash): (
                            Vec<RustBytes>,
                            Option<RustBytes>,
                        ) = result.to_rust();

                        Ok(InitProtocolContextResult {
                            supported_protocol_hashes,
                            genesis_commit_hash,
                        })
                    }
                    Err(e) => Err(TezosStorageInitError::from(e)),
                }
            }
        )
    })
}

pub fn genesis_result_data(
    context_hash: RustBytes,
    chain_id: RustBytes,
    protocol_hash: RustBytes,
    genesis_max_operations_ttl: u16,
) -> Result<Result<CommitGenesisResult, GetDataError>, OcamlError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(rt, (context_hash_ref, chain_id_ref), {
            let context_hash = to_ocaml!(rt, context_hash, context_hash_ref);
            let chain_id = to_ocaml!(rt, chain_id, chain_id_ref);
            let protocol_hash = to_ocaml!(rt, protocol_hash);
            let genesis_max_operations_ttl = OCaml::of_i32(genesis_max_operations_ttl as i32);

            let result = ocaml_call!(tezos_ffi::genesis_result_data(
                rt,
                rt.get(&context_hash),
                rt.get(&chain_id),
                protocol_hash,
                genesis_max_operations_ttl
            ));
            match result {
                Ok(result) => {
                    let (
                        block_header_proto_json,
                        block_header_proto_metadata_json,
                        operations_proto_metadata_json,
                    ) = result.to_rust();
                    Ok(CommitGenesisResult {
                        block_header_proto_json,
                        block_header_proto_metadata_json,
                        operations_proto_metadata_json,
                    })
                }
                Err(e) => Err(GetDataError::from(e)),
            }
        })
    })
}

type CallRequestFn<REQUEST, RESPONSE> = OCamlFn1<REQUEST, RESPONSE>;

/// Calls ffi function like request/response
pub fn call<REQUEST, RESPONSE>(
    ocaml_function: CallRequestFn<REQUEST, RESPONSE>,
    request: REQUEST,
) -> Result<Result<RESPONSE, CallError>, OcamlError>
where
    REQUEST: ToOCaml<REQUEST> + Send + 'static,
    RESPONSE: FromOCaml<RESPONSE> + Send + 'static,
{
    runtime::execute(move |rt: &mut OCamlRuntime| {
        let ocaml_request = to_ocaml!(rt, request);
        let result = ocaml_call!(ocaml_function(rt, ocaml_request));
        match result {
            Ok(response) => Ok(response.to_rust()),
            Err(e) => Err(CallError::from(e)),
        }
    })
}

/// Applies block to context
pub fn apply_block(
    request: ApplyBlockRequest,
) -> Result<Result<ApplyBlockResponse, CallError>, OcamlError> {
    call(tezos_ffi::apply_block, request)
}

/// Begin construction initializes prevalidator and context for new operations based on current head
pub fn begin_application(
    request: BeginApplicationRequest,
) -> Result<Result<BeginApplicationResponse, CallError>, OcamlError> {
    call(tezos_ffi::begin_application, request)
}

/// Begin construction initializes prevalidator and context for new operations based on current head
pub fn begin_construction(
    request: BeginConstructionRequest,
) -> Result<Result<PrevalidatorWrapper, CallError>, OcamlError> {
    call(tezos_ffi::begin_construction, request)
}

/// Validate operation - used with prevalidator for validation of operation
pub fn validate_operation(
    request: ValidateOperationRequest,
) -> Result<Result<ValidateOperationResponse, CallError>, OcamlError> {
    call(tezos_ffi::validate_operation, request)
}

pub fn call_protocol_rpc(
    request: ProtocolRpcRequest,
) -> Result<Result<ProtocolRpcResponse, ProtocolRpcError>, OcamlError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        let ocaml_request = to_ocaml!(rt, request);
        let result = ocaml_call!(tezos_ffi::call_protocol_rpc(rt, ocaml_request));
        result.unwrap().to_rust()
    })
}

/// Call helpers_preapply_operations shell service
pub fn helpers_preapply_operations(
    request: ProtocolRpcRequest,
) -> Result<Result<HelpersPreapplyResponse, CallError>, OcamlError> {
    call(tezos_ffi::helpers_preapply_operations, request)
}

/// Call helpers_preapply_block shell service
pub fn helpers_preapply_block(
    request: ProtocolRpcRequest,
) -> Result<Result<HelpersPreapplyResponse, CallError>, OcamlError> {
    call(tezos_ffi::helpers_preapply_block, request)
}

/// Call compute path
pub fn compute_path(
    request: ComputePathRequest,
) -> Result<Result<ComputePathResponse, CallError>, OcamlError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        let ocaml_request = to_ocaml!(rt, request.operations);
        let result = ocaml_call!(tezos_ffi::compute_path(rt, ocaml_request));
        match result {
            Ok(response) => {
                let operations_hashes_path: Vec<FfiPath> = response.to_rust();
                let operations_hashes_path = operations_hashes_path
                    .into_iter()
                    .map(|path| path.0)
                    .collect();
                Ok(ComputePathResponse {
                    operations_hashes_path,
                })
            }
            Err(e) => Err(CallError::from(e)),
        }
    })
}

pub fn decode_context_data(
    protocol_hash: RustBytes,
    key: Vec<String>,
    data: RustBytes,
) -> Result<Result<Option<String>, ContextDataError>, OcamlError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(rt, (protocol_hash_ref, key_list_ref), {
            let protocol_hash = to_ocaml!(rt, protocol_hash, protocol_hash_ref);
            let key_list = to_ocaml!(rt, key, key_list_ref);
            let data = to_ocaml!(rt, data);

            let result = ocaml_call!(tezos_ffi::decode_context_data(
                rt,
                rt.get(&protocol_hash),
                rt.get(&key_list),
                data
            ));

            match result {
                Ok(decoded_data) => {
                    let decoded_data = decoded_data.to_rust();
                    Ok(decoded_data)
                }
                Err(e) => Err(ContextDataError::from(e)),
            }
        })
    })
}

pub fn assert_encoding_for_protocol_data(
    protocol_hash: RustBytes,
    protocol_data: RustBytes,
) -> Result<Result<(), ProtocolDataError>, OcamlError> {
    runtime::execute(move |rt: &mut OCamlRuntime| {
        ocaml_frame!(rt, (protocol_hash_ref), {
            let protocol_hash = to_ocaml!(rt, protocol_hash, protocol_hash_ref);
            let data = to_ocaml!(rt, protocol_data);

            let result = ocaml_call!(tezos_ffi::assert_encoding_for_protocol_data(
                rt,
                rt.get(&protocol_hash),
                data
            ));

            match result {
                Ok(_) => Ok(()),
                Err(e) => Err(ProtocolDataError::from(e)),
            }
        })
    })
}
