use dep::std::collections::bounded_vec::BoundedVec;
use crate::Sequence;
mod HeaderFields {
    global from: [u8; _] = comptime { "from".as_bytes() };
    global to: [u8; _] = comptime { "to".as_bytes() };
    global subject: [u8; _] = comptime { "subject".as_bytes() };
    global date: [u8; 4] = comptime { "date".as_bytes() };
    global message_id: [u8; _] = comptime { "message-id".as_bytes() };
    global mime_version: [u8; _] = comptime { "mime-version".as_bytes() };
    global content_type: [u8; _] = comptime { "content-type".as_bytes() };
    global content_transfer_encoding: [u8; _] = comptime { "content-transfer-encoding".as_bytes() };
    global content_id: [u8; _] = comptime { "content-id".as_bytes() };
}

// CRLF
global CR: u8 = 0x0D;
global LF: u8 = 0x0A;

pub fn tes() {
    let header = BoundedVec::new();
    let sequence = Sequence { index: 0, length: 100 };
    #[header_constraint_macro]
    constrain_header_field(header, sequence);
}

/**
 * Constrains a header field to be within 
 */
pub fn constrain_header_field<
    let MAX_FIELD_LENGTH: u32,
    let HEADER_FIELD_NAME_LENGTH: u32,
>(
    header: BoundedVec<u8, MAX_FIELD_LENGTH>,
    sequence: Sequence
) {
    // check that the sequence is within bounds
    assert(sequence.index + sequence.length <= header.len(), "Header field out of bounds");
    // if the sequence is not the start, check for a newline
    if sequence.index != 0 {
        assert(header.get_unchecked(sequence.index - 2) == CR, "Header field must start with CRLF");
        assert(header.get_unchecked(sequence.index - 1) == LF, "Header field must start with CRLF");
    }
    // if the sequence is not the end, check for a newline
    if sequence.index + sequence.length != header.len() {
        assert(header.get_unchecked(sequence.index + sequence.length) == CR, "Header field must end with CRLF");
        assert(header.get_unchecked(sequence.index + sequence.length + 1) == LF, "Header field must end with CRLF");
    }
}

// pub comptime fn header_type()

comptime fn header_constraint_macro<let N: u32>(
    f: FunctionDefinition,
    header_name: str<N>,
) {
    let body = f.body().as_block().unwrap();
    let mut body_pre = body.fold(
        quote {},
        |full_quote: Quoted, expr: Expr| {
            let expr_quote = expr.quoted();
            quote {
                $full_quote
                $expr_quote
            }
        }
    );
    let name_as_bytes = header_name.as_bytes();
    let header_specific = quote {
        global const header_type: [u8; $N] = $name_as_bytes;
        for i in 0..$N {
            assert(header[sequence.index + i] == header_type[i], "Header field name does not match $name_as_bytes");
        }
    };
    let body_quote = quote {
        $header_specific
        $body_pre
    };
    let body_expr = body_quote.as_expr().expect(f"Body is not an expression: {body_quote}");
    //  body_expr.expect(f"Body is not an expression: {body_quote}")
    f.set_body(body_expr);
}

// comptime fn f2<let N: u32>(
//     f: FunctionDefinition
// ) -> Quoted {
//     quote {
//         for i in 0..$N {
//             assert(header[sequence.index + i] == 0, "Header field name does not match $name_as_bytes");
//         }
//     }
// }