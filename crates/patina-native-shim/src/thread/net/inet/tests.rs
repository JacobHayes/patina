//! Unit tests for this module and its focused submodules.

use super::{Direction, Urgent};

#[test]
fn the_urgent_byte_stops_a_receive_arrives_with_its_byte_and_goes_once_passed() {
    let mut direction = Direction {
        written: 4,
        taken: 0,
        urgent: Some(Urgent {
            at: 3,
            byte: b'!',
            read: false,
        }),
    };
    // Three bytes before the mark; the mark is known once its byte is in.
    assert_eq!(direction.before_mark(), Some(3));
    assert!(direction.arrived(3).is_none());
    assert!(direction.arrived(4).is_some());
    direction.took(3);
    assert_eq!(direction.before_mark(), Some(0));
    assert!(direction.urgent.is_some());
    // Taking the byte itself (skipped, or read inline) passes the mark.
    direction.took(1);
    assert!(direction.urgent.is_none());
    assert_eq!(direction.before_mark(), None);
}
