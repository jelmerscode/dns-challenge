//! We need a function that decodes a DNS name that is encoded in the 'RFC1035
//! compression format' to the usual representation like "www.tweede.golf".
//!
//! A DNS name consists of parts separated by periods, e.g., the domain name
//! above has three parts: "www", "tweede", and "golf".
//!
//! In RFC1035 format, these parts are encoded by prefixing them with one byte
//! indicating the length, followed by the bytes that comprise the part. The
//! domain name itself is zero-terminated (i.e., an "empty part" signifies the
//! end of a domain name); the periods between parts are not encoded.
//!
//! So, for example, "mailcrab.tweedegolf.nl" can be encoded as:
//!
//! 0x08 mailcrab 0x0A tweedegolf 0x02 nl 0x00
//! or, in Rust's bytestring notation:
//!
//! b"\x08mailcrab\x0Atweedegolf\x02nl\0"
//!
//! There are some restrictions:
//! - The maximum size of a part is 63 bytes.
//! - The maximum size of a full domain name (including periods) is 255 bytes.
//! - A domain name cannot be empty.
//!
//! ASSIGNMENT 1: Ignore the `_backlog` argument for now, and implement this
//! functionality. The test case `simple` should now pass. This test case is
//! minimal so feel free to improve the test cases, or even add fuzzing, etc.
//!
//! Make a commit after this point.
//!
//! ---
//!
//! The RFC1035 compression format is used in the context of a larger packet
//! consisting of multiple domain names, where suffixes occur multiple times,
//! e.g. a packet could consist of "mailcrab.tweedegolf.nl",
//! "mail.tweedegolf.nl", "mattermost.tweedegolf.nl", etc.
//!
//! To avoid having to encode the same suffix multiple times, we can jump to an
//! earlier suffix in the packet.
//!
//! This is done by, in place of encoding a part, encoding a 14-bit absolute
//! index in two bytes. The first byte will have its two most significant bits
//! set to 1, followed by the 6 most significant bits of the 14-bit index. The
//! second byte will hold the 8 least significant bits of the index. Or in other
//! words, this index is encoded in big-endian format with the first byte
//! bitwise OR'ed with 0xC0.
//!
//! So for example, this set of records encodes for "tweedegolf.nl",
//! "mailcrab.tweedegolf.nl", "mail.tweedegolf.nl" and
//! "secret.mailcrab.tweedegolf.nl".
//!
//! b"\x0Atweedegolf\x02nl\0\x08mailcrab\xC0\x00\x04mail\xC0\x00\x06secret\xC0\x0F"
//!
//! E.g. "mailcrab.tweedegolf.nl" starts at index 15, where the part for
//! "mailcrab" is encoded, followed by a jump back to index 0, where
//! "tweedegolf" followed by "nl" is encoded. You can find "mail.tweedegolf.nl"
//! at index 26 and "secret.mailcrab.tweedegolf.nl" at index 33.
//!
//! ASSIGNMENT 2: Add this functionality to `decode_dns_name`. The first
//! argument is a slice pointing to the current DNS name to be decoded; the
//! second contains the entire packet. Of course, the first argument is expected
//! to be subslice of the second argument. The second test case should now pass.
//! Again, the test case is the bare minimum.
//!
//! Make a commit after this point.
//!
//! ---
//!
//! ASSIGNMENT 3 (optional): use "cargo fuzz" to test your implementation, did
//! you find any nice bugs?
//!
//! Make a commit after this point.
//!
//! ---
//!
//! Make nice commits.
//! 
//! For a better(?) explanation read section 4.1.4 of RFC 1035: https://www.ietf.org/rfc/rfc1035.txt
//!
//! NOTE: You're only allowed to use the Rust standard library, ob-vi-ous-ly.

pub fn decode_dns_name(input: &[u8], _backlog: &[u8]) -> Option<Box<[u8]>> {
    let mut index = 0;
    let mut parts: Vec<u8> = Vec::new();
    let mut no_of_parts = 0;

    while index < input.len() {
        // read the length of the part
        let length = input[index] as usize;
        index += 1;

        match length {
            0 => index = input.len(), // length byte indicates end of name
            64.. => return None, // invalid length size
            _ => {

                if index + length + no_of_parts > 255 || index + length >= input.len() {
                    // invalid length
                    return None
                }
                if let Some(part) = input.get(index..(index + length)) {
                    // if this isn't the first part, add a seperator
                    if no_of_parts > 0 { parts.push(b'.') };
                    parts.extend_from_slice(part);
                    index += length;
                    no_of_parts += 1;
                } else {
                    // specified range for part out of bounds
                    return None;
                }
                    
            }
        }
    }

    match parts.len() {
        0 => None, // name cannot be empty
        _ => Some(parts.into_boxed_slice())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simple() {
        let input = b"\x06google\x03com\0";

        assert_eq!(
            decode_dns_name(&input[..], &[]).as_deref().unwrap(),
            b"google.com"
        );
    }

    #[test]
    fn empty() {
        let input = b"";

        assert!(decode_dns_name(&input[..], &[]).is_none());
    }

    #[test]
    fn length_out_of_bounds() {
        let input = b"\x03co\0";

        assert!(decode_dns_name(&input[..], &[]).is_none());
    }

    #[test]
    fn simple_backref() {
        let pkt = b"\x06google\x03com\0\x03www\xC0\x00";

        assert_eq!(
            decode_dns_name(&pkt[12..], &pkt[..]).as_deref().unwrap(),
            b"www.google.com"
        );
    }
}
