// In this exercise we write a function that decodes a DNS name that is encoded in
// the 'DNS format' to the usual representation like "www.tweede.golf".
//
// A DNS name consists of parts separated by periods, e.g., the domain name above has
// three parts: "www", "tweede", and "golf".
//
// In DNS format, these parts are 'run length encoded', and the parts themselves
// are zero-delimited (i.e., an "empty part" signifies the end of a domain name);
// the periods between parts are not encoded.
//
// A part is encoded with one prefix byte indicating the length, followed by the
// bytes that consist of a part.
//
// So, for example, "mailcrab.tweedegolf.nl" would be encoded as:
//
// 0x08 mailcrab 0x0A tweedegolf 0x02 nl 0x00
// or in Rust's bytestring notation:
//
// b"\x08mailcrab\x0Atweedegolf\x02nl\0"
//
// ASSIGNMENT 1: implement this with the function `decode_dns_name`; ignore the
// argument for `_backlog` right now. After finishing the assignment, the test
// case `simple` should pass. This test case is a bit minimal,
// so feel free to add more test cases or fuzzers, etc.
//
// Please make a 'git commit' after this point.
//
// ---
//
// The DNS format is usually used in a large record consisting of multiple
// domain names, where suffixes occur multiple times, e.g. a record could consist of
// "mailcrab.tweedegolf.nl", "mail.tweedegolf.nl", "mattermost.tweedegolf.nl", etc.
// To avoid having to encode those suffixes multiple times, a simple compression scheme
// is used where in the DNS format we can jump to an earlier suffix in the backlog.
//
// This is indicated by, in place of encoding a part, encoding a 14-bit absolute index
// in two bytes; the first byte will have the two most significant bits set to 1, followed
// by the 6 most significant bits of the 14-bit index, the second byte will hold the 8 least
// significant bits of the index. Or in other words, the index is encoded in big-endian format
// where the first byte is bitwise OR'ed with 0xC0.
//
// So for example, this set of records encodes for "mailcrab.tweedegolf.nl", "mail.tweedegolf.nl"
// and "secret.mailcrab.tweedegolf.nl":
//
// b"\x0Atweedegolf\x02nl\0\x08mailcrab\xC0\x00\x04mail\xC0\x00\x06secret\xC0\x0f"
//
// E.g. "mailcrab.tweedegolf.nl" starts at index 15, where the part for "mailcrab" is encoded,
// followed by a jump back to index 0, where "tweedegolf" followed by "nl" is encoded.
//
// ASSIGNMENT 2: add this functionality to `decode_dns_name`. The first argument is a slice
// capturing the current DNS name to be decoded; the second contains the entire backlog.
// Of course, the first argument is allowed to be subslice of the second argument.
// The second test case should pass. Think about better test cases as well.
//
// Please make a 'git commit' after this point.
//
// ---
//
// ASSIGNMENT 3 (extra): use "cargo fuzz" to test your implementation, did you find any nice bugs?
//
// Please make a 'git commit' after this point.
//
// ---
//
// Share your solution with us (Marc and Tamme) by making a MR on the repository "dns-challenge":
// https://tgrep.nl/tweedegolf/dns-challenge/. Make nice commits.
//
// For a better(?) explanation read section 4.4.1 of RFC 1035:
// https://www.ietf.org/rfc/rfc1035.txt
//
// NOTE: You don't need any dependencies for these assignments, and we strongly suspect
// you are going to ruin the exercise if you seek them out. So please don't. :-)

pub fn decode_dns_name(input: &[u8], _backlog: &[u8]) -> Option<Box<[u8]>> {
    todo!()
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
    fn simple_backref() {
        let pkt = b"\x06google\x03com\0\x03www\xC0\0x00";

        assert_eq!(
            decode_dns_name(&pkt[12..], &pkt[..]).as_deref().unwrap(),
            b"www.google.com"
        );
    }
}
