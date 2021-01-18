use failure::Error;
use nom::number::streaming::{be_i8, be_u8, be_u16, be_u32};
use nom::{IResult, Err};
use nom::error::ErrorKind;
use nom::Err::Failure;
use crypto::hash::HashType;

use crate::p2p::encoding::prelude::*;
use crate::p2p::binary_message::BinaryMessage;

// TODO : write a Hash macro which reads byte based on Hash type
named!(operation_hash,
    take!(32)
);

named!(block_hash<Vec<u8>>,
    count!(be_u8, 32)
);

named!(operation_list_list_hash<Vec<u8>>,
    count!(be_u8, 32)
);

named!(pub operation<Operation>,
    do_parse!(
        branch_hash: block_hash >>
        data_vec : many0!(complete!(be_u8)) >>
        (Operation {
            branch: branch_hash,
            data: data_vec,
            body: Default::default(),
        })
    )
);

named!(opp<Operation>,
    do_parse!(
    size : be_u32 >>
    opss : operation >>
    (opss)
    )
);

named!(operations<Vec<Operation>>,
    do_parse!(
        ops: many0!(complete!(length_value!(be_u32, operation)))
             >>
        (ops)
    )
);

named!(operation_for_blocks_message<PeerMessage>,
    do_parse!(
        ops_for_block: operation_for_block >>
        ops_hashes_path: call!(path_encoding_depth, 0) >>
        ops: alt!(many0!(
            complete!(
            length_value!(be_u32,
                operation)
            )) | value!(vec!())) >>
        (PeerMessage::from(OperationsForBlocksMessage::new(ops_for_block, ops_hashes_path, ops)))
    )
);

named!(operation_for_blocks_message1<PeerMessage>,
    do_parse!(
        ops_for_block: operation_for_block >>
        ops_hashes_path: path_encoding >>
        ops: many0!(
            complete!(length_value!(be_u32,
                operation))
            ) >>
        (PeerMessage::from(OperationsForBlocksMessage::new(ops_for_block, ops_hashes_path, ops)))
    )
);
named!(operation_for_block<OperationsForBlock>,
    do_parse!(
        hash: block_hash >>
        validation_pass: be_i8 >>
        (OperationsForBlock::new(hash, validation_pass))
    )
);

named!(get_operations<Vec<&[u8]>>,
    do_parse!(
        op_hashes: length_value!(be_u32,
            many0!(complete!(operation_hash))
        ) >>
        (op_hashes)
    )
);

named!(get_operations_for_block<PeerMessage>,
    do_parse!(
        res: length_value!(be_u32,
                many0!(complete!(operation_for_block))
            ) >>
        (PeerMessage::from(GetOperationsForBlocksMessage::new(res)))
    )
);

named!(peer_message_response<PeerMessageResponse>,
     do_parse!(
         data: length_value!(be_u32, 
            switch!(be_u16,
                    0x60 => call!(get_operations_for_block) |
                    0x61 => call!(operation_for_blocks_message)
                )
            ) >>
         (PeerMessageResponse::from(data))
   )
);

pub fn path_left_depth(input: &[u8], depth: u32) -> IResult<&[u8], Path> { 
   if depth > 20 {
        return Err(Err::Failure(error_position!(input, ErrorKind::TooLarge)));
    }
    let (rem, path) = try_parse!(input, call!(path_encoding_depth, depth));
    let (rem1, right) = try_parse!(rem, operation_list_list_hash);
    Ok((rem1,
    Path::Left(
            Box::new(
                PathLeft::new(path, right, Default::default())
                )
            )
    ))
}

pub fn path_right_depth(input: &[u8], depth : u32) -> IResult<&[u8], Path> { 
    // Note: value 20 is just for demo
   if depth > 20 {
        return Err(Err::Failure(error_position!(input, ErrorKind::TooLarge)));
    }
    let (rem, left) = try_parse!(input, operation_list_list_hash);
    let (rem1, path)= try_parse!(rem, call!(path_encoding_depth, depth));
       Ok((rem1,
        Path::Right(
            Box::new(
                PathRight::new(left, path,  Default::default())
                )
            )
        )
    )
}

named!(path_left<Path>, 
    do_parse!(
        path: path_encoding >>
        right: operation_list_list_hash >>
        (Path::Left(
            Box::new(
                PathLeft::new(path, right, Default::default())
                )
            )
        )
    )
);

named!(path_right<Path>, 
    do_parse!(
        left: operation_list_list_hash >>
        path: path_encoding >>
        (Path::Right(
            Box::new(
                PathRight::new(left, path,  Default::default())
                )
            )
        )
    )
);

named!(path_encoding<Path>,
    do_parse!(
    path: switch!(be_u8,
                0xF0 => call!(path_left) |
                0x0F => call!(path_right) |
                0x00 => value!(Path::Op)
                ) >>
    (path)
    )
);

named_args!(path_encoding_depth(depth: u32)<Path>,
    do_parse!(
    path: switch!(be_u8,
                0xF0 => call!(path_left_depth, depth+1) |
                0x0F => call!(path_right_depth, depth+1) |
                0x00 => value!(Path::Op)
                ) >>
    (
        path
    )
    )
);

named!(dynamic<(u32, u16, OperationsForBlock)>,
    do_parse!(
        size : be_u32 >>
        tag : be_u16 >>
        op_for_block: operation_for_block >>
        (size, tag, op_for_block)
    )
); 

#[test]
fn get_block_hash() -> Result<(), Error> {
    let bh = hex::decode("ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa")?;
    let hash = block_hash(&bh).unwrap();
    println!("blockHash {:?} ",&hash.1);
    assert_eq!(
            "BMWmj9CTojf7AnA8ZQFWGkh1cXB6FkST8Ey5coaeHX6cVNAZqA6",
            HashType::BlockHash.hash_to_b58check(&hash.1)
            ); 
    Ok(())
}
#[test]
fn get_op_for_block() -> Result<(), Error> {
    let bh = hex::decode("ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa09")?;
    let op = operation_for_block(&bh).unwrap().1;
    println!("OperationForBlock {:?} ", &op);
    assert_eq!(
            "BMWmj9CTojf7AnA8ZQFWGkh1cXB6FkST8Ey5coaeHX6cVNAZqA6",
            HashType::BlockHash.hash_to_b58check(op.hash())
            );
    assert_eq!(9, op.validation_pass()); 
    Ok(())
}

#[test]
fn get_ops_for_block() -> Result<(), Error> {
   let bh = hex::decode("00000084ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa01ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa02ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa00ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa03")?;
 let ops = get_operations_for_block(&bh).unwrap().1;
 println!("operations for block: {:?}", &ops);
    match ops {
        PeerMessage::GetOperationsForBlocks(message) => {
            let operations = message.get_operations_for_blocks();
            assert_eq!(4, operations.len());
            assert_eq!(
                    "BMWmj9CTojf7AnA8ZQFWGkh1cXB6FkST8Ey5coaeHX6cVNAZqA6",
                    HashType::BlockHash.hash_to_b58check(operations[0].hash())
                    );
            assert_eq!(1, operations[0].validation_pass());
        }
         _ => panic!("Unsupported encoding: {:?}", ops),
    }
    Ok(())
}

#[test]
fn get_peer_message_response() -> Result<(), Error> {
        let message_bytes = hex::decode("0000008a006000000084ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa01ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa02ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa00ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa03")?;
    let messages = peer_message_response(&message_bytes).unwrap().1;
    assert_eq!(1, messages.messages().len());

    let message = messages.messages().get(0).unwrap();
    match message {
        PeerMessage::GetOperationsForBlocks(message) => {
            let operations = message.get_operations_for_blocks();
            assert_eq!(4, operations.len());
            assert_eq!(
                    "BMWmj9CTojf7AnA8ZQFWGkh1cXB6FkST8Ey5coaeHX6cVNAZqA6",
                    HashType::BlockHash.hash_to_b58check(operations[0].hash())
                    );
            assert_eq!(1, operations[0].validation_pass());
        }
         _ => panic!("Unsupported encoding: {:?}", message),
    }
    Ok(())
}

#[test]
fn wrong_message() -> Result<(), Error> {
        let wrong = hex::decode("0000098a006000000084ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa01ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa02ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa00ed4197d381a4d4f56be30bf7157426671276aa187bbe0bb9484974af59e069aa03")?;
    let wrong_message = peer_message_response(&wrong);
    assert!(wrong_message.is_err());
    println!("{:?}", wrong_message);
    Ok(())
}

#[test]
fn get_operations_for_blocks_right() -> Result<(), Error> {
        let message_bytes = hex::decode("000000660061b12238a7c3577d725939970800ade6b82d94a231e855b46af46c37850dd02452030ffe7601035ca2892f983c10203656479cfd2f8a4ea656f300cd9d68f74aa625870f7c09f7c4d76ace86e1a7e1c7dc0a0c7edcaa8b284949320081131976a87760c300")?;
let pmessage = peer_message_response(&message_bytes).unwrap().1;
println!("{:?}" , pmessage);
assert_eq!(1, pmessage.messages().len());

let message = pmessage.messages().get(0).unwrap();
match message {
    PeerMessage::OperationsForBlocks(message) => {
        assert_eq!(
                "BM4Hyf4ay3u2PcUBmumTEPcWW8Z7t45HXGZAjLNnenSC2f8bLte",
                HashType::BlockHash.hash_to_b58check(message.operations_for_block().hash())
                );

        match message.operation_hashes_path() {
            Path::Right(path) => {
                assert_eq!(
                        "LLobFmsoFEGPP3q9ZxpE84rH1vPC1uKqEV8L1x8zUjGwanEYuHBVB",
                        HashType::OperationListListHash.hash_to_b58check(path.left())
                        );
                match path.path() {
                    Path::Right(path) => {
                        assert_eq!(
                                "LLoaGLRPRx3Zf8kB4ACtgku8F4feeBiskeb41J1ciwfcXB3KzHKXc",
                                HashType::OperationListListHash.hash_to_b58check(path.left())
                                );
                        match path.path() {
                            Path::Op => Ok(()),
                                _ => panic!("Unexpected path: {:?}. Was expecting Path::Op.", path),
                        }
                    }
                    _ => panic!("Unexpected path: {:?}. Was expecting Path::Right.", path),
                }
            }
            _ => panic!(
                    "Unexpected path: {:?}. Was expecting Path::Right.",
                    message.operation_hashes_path()
                    ),
        }
    }
    _ => panic!("Unsupported encoding: {:?}", message),
}
}
#[test]
fn get_operations_for_blocks_left() -> Result<(), Error> {
    let message_bytes = hex::decode("0000027300613158c8503e7cd436d09a8a6320cd57014870a96f178915be25551e435d0830ab00f0f0007c09f7c4d76ace86e1a7e1c7dc0a0c7edcaa8b284949320081131976a87760c30a37f18e2562ae14388716247be0d4e451d72ce38d1d4a30f92d2f6ef95b4919000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb6d1852a1f397619b16f08121fb01d43a9bf4ded283ab0d96fd114028251690506a7ec514f0b297b6cdc8ff54a658f27f7635d201c61479cd48007c0096752fb0c000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb62b8768820e6b7343c32382544d0fa0f044289fd1b86ee5c66e36396bc9bc2492314543667770959449943d222ffd7f7cd8e3ad8eda9d21a8a5e9e34c73c0c9e3000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb6c5d4ac0ba67f6509fec4ae196d1cb7ccf8ee7a35bc06d362d69291631a5a07b511252c70d59ff94dc4071525dd6c22354349702c9821d80c748a15913f11b1d1000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb63d61de83c6f71ca631903f29be9040f63dbf5d00d7994a8420210270aa2c37e245ce70e8f4d7d384f342f7e6b6797c5f237ae1846a8b8652838663d1d0df91a0000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb6c69c651e14357c3a895cd6465fc1e3b1fd19b0d805efae484f2632e006101b9c80c28c92dcfbf58b99392b2108b286fd28039ddd72294929c2fbf9dda65acf01")?;

let pmessage = peer_message_response(&message_bytes).unwrap().1;
println!("{:?}" , pmessage);
    assert_eq!(1, pmessage.messages().len());

    let message = pmessage.messages().get(0).unwrap();
    match message {
        PeerMessage::OperationsForBlocks(message) => {
            assert_eq!(
                    "BL61qJKRdXg6i628H62DyDqBNotK7f6CZrHGv4k7jEe8a86B7n8",
                    HashType::BlockHash.hash_to_b58check(message.operations_for_block().hash())
                    );
            assert_eq!(
                    5,
                    message.operations().len(),
                    "Was expecting 5 operations but found {}",
                    message.operations().len()
                    );
            match message.operation_hashes_path() {
                Path::Left(path) => {
                    assert_eq!(
                            "LLoZQD2o1hNgoUhg6ha9dCVyRUY25GX1KN2TttXW2PZsyS8itbfpK",
                            HashType::OperationListListHash.hash_to_b58check(path.right())
                            );
                    match path.path() {
                        Path::Left(path) => {
                            assert_eq!(
                                    "LLoaGLRPRx3Zf8kB4ACtgku8F4feeBiskeb41J1ciwfcXB3KzHKXc",
                                    HashType::OperationListListHash.hash_to_b58check(path.right())
                                    );
                            match path.path() {
                                Path::Op => Ok(()),
                                    _ => panic!("Unexpected path: {:?}. Was expecting Path::Op.", path),
                            }
                        }
                        _ => panic!("Unexpected path: {:?}. Was expecting Path::Right.", path),
                    }
                }
                _ => panic!(
                        "Unexpected path: {:?}. Was expecting Path::Right.",
                        message.operation_hashes_path()
                        ),
            }
        }
        _ => panic!("Unsupported encoding: {:?}", message),
    }
}

#[test]
fn get_operations1() -> Result<(), Error> {
let b = hex::decode("000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb6d1852a1f397619b16f08121fb01d43a9bf4ded283ab0d96fd114028251690506a7ec514f0b297b6cdc8ff54a658f27f7635d201c61479cd48007c0096752fb0c000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb62b8768820e6b7343c32382544d0fa0f044289fd1b86ee5c66e36396bc9bc2492314543667770959449943d222ffd7f7cd8e3ad8eda9d21a8a5e9e34c73c0c9e3000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb6c5d4ac0ba67f6509fec4ae196d1cb7ccf8ee7a35bc06d362d69291631a5a07b511252c70d59ff94dc4071525dd6c22354349702c9821d80c748a15913f11b1d1000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb63d61de83c6f71ca631903f29be9040f63dbf5d00d7994a8420210270aa2c37e245ce70e8f4d7d384f342f7e6b6797c5f237ae1846a8b8652838663d1d0df91a0000000658a7912f9de23a446748861d2667ffa3b4463ed236689492c74703cef598e6f3f0000002eb6c69c651e14357c3a895cd6465fc1e3b1fd19b0d805efae484f2632e006101b9c80c28c92dcfbf58b99392b2108b286fd28039ddd72294929c2fbf9dda65acf01")?;
let ops = operations(&b).unwrap().1;
assert_eq!(5, ops.len());
println!("{:?}", ops);
Ok(())
}

#[test]
fn left_recursion() -> Result<(), Error> {
let b = hex::decode("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0")?;
let p = path_encoding_depth(&b, 0);
assert_eq!(p, Err(Err::Failure(nom::error::Error { input: &b[21..], code: ErrorKind::TooLarge})));
println!("{:?}", p);
Ok(())
}

#[test]
fn bench_correct() -> Result<(), Error> {
    let message_bytes = hex::decode("0090304939374e4f0f260928d4879fd5f359b4ff146f3fd37142436fb8ce1ab57af68648964efff6ca56a82b61185aec6538fa000125a2a1468416d65247660efcba15111467b9feab07dfc3dafac2d2a8c4c6dbca0b97b7239bcc4bd7ab2229b9c506022870539f6505ff56af81e5d344baa82465bae2a023afa5de27a6600e4dc85b050471ef8c3d887bb7a65700caaa98").unwrap();
    let o = operation(&message_bytes).unwrap().1;
    let operation = Operation::from_bytes(message_bytes)?;
        assert_eq!(
                    HashType::BlockHash.hash_to_b58check(&o.branch()),
                        HashType::BlockHash.hash_to_b58check(&operation.branch())
                            );
            assert_eq!(&hex::encode(&o.data()), &hex::encode(&operation.data()));

    println!("{:?}", o);
    Ok(()) // making sure parser does not crash
}
