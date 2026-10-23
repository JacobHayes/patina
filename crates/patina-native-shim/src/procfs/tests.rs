use super::*;

/// An open file whose text each [`made`](Texts::made) call makes anew,
/// numbered, so a test sees which text a read served.
struct Texts(u32);

impl Texts {
    fn made(&mut self) -> Vec<u8> {
        self.0 += 1;
        format!("text {}\n", self.0).into_bytes()
    }

    /// `read` (`at: None`) or `pread` (`Some`) through the state machine
    /// [`super::read_with`] drives, making the text when a step wants it.
    fn read(&mut self, open: &mut Open, len: usize, at: Option<u64>) -> String {
        self.read_into(open, len, at, &mut |_| Ok(())).unwrap()
    }

    /// [`read`](Self::read) with the bytes handed to `deliver`.
    fn read_into(
        &mut self,
        open: &mut Open,
        len: usize,
        at: Option<u64>,
        deliver: &mut dyn FnMut(&[u8]) -> Result<(), c_int>,
    ) -> Result<String, c_int> {
        let mut fresh = None;
        loop {
            if let Some(bytes) = open.read_step(&mut fresh, len, at, deliver)? {
                return Ok(String::from_utf8(bytes).unwrap());
            }
            fresh = Some(self.made());
        }
    }

    /// `lseek(SEEK_SET)` as [`super::seek`] drives it.
    fn seek(&mut self, open: &mut Open, target: u64) {
        let mut fresh = None;
        while open.seek_step(&mut fresh, target).is_none() {
            fresh = Some(self.made());
        }
    }
}

fn opened() -> Open {
    Open {
        node: Node::Machine(Machine::Uptime),
        text: None,
        read_pos: 0,
        pos: 0,
    }
}

/// A read that goes on where the last ended keeps the text it was served
/// from, to its end; a read or a seek elsewhere, `pread` included, makes it
/// again, and a seek to the start leaves that to the next read.
#[test]
fn the_text_is_made_again_only_where_a_read_does_not_continue() {
    let mut texts = Texts(0);
    let mut open = opened();
    let whole = String::from_utf8(texts.made()).unwrap();
    texts.0 = 0;
    // Nothing is made before the first read.
    texts.seek(&mut open, 0);
    assert_eq!(texts.0, 0);
    let first = texts.read(&mut open, 3, None);
    let rest = texts.read(&mut open, usize::MAX, None);
    assert_eq!(format!("{first}{rest}"), whole, "one text across the reads");
    assert_eq!(
        texts.read(&mut open, 8, None),
        "",
        "past the end, no new text"
    );
    assert_eq!(texts.0, 1);
    assert_eq!(open.pos as usize, whole.len());
    // A pread elsewhere makes the text again and keeps the position.
    assert_eq!(texts.read(&mut open, 6, Some(0)), "text 2");
    assert_eq!(open.pos as usize, whole.len());
    // A read at the description's position is elsewhere now too.
    assert_eq!(texts.read(&mut open, 8, None), "");
    assert_eq!(texts.0, 3);
    // A seek to where the last read ended keeps the text.
    let pos = open.read_pos;
    texts.seek(&mut open, pos);
    assert_eq!(texts.0, 3);
    // A seek elsewhere makes it at once; one to the start at the next read.
    texts.seek(&mut open, 1);
    assert_eq!(texts.0, 4);
    assert_eq!(texts.read(&mut open, 5, None), "ext 4");
    texts.seek(&mut open, 0);
    assert_eq!(texts.0, 4);
    assert_eq!(texts.read(&mut open, 6, None), "text 5");
}

/// A read of no bytes neither makes the text nor moves where the last read
/// ended, so the next read makes the text as it would have without it.
#[test]
fn a_read_of_no_bytes_changes_nothing() {
    let mut texts = Texts(0);
    let mut open = opened();
    assert_eq!(texts.read(&mut open, 0, None), "");
    assert_eq!(texts.0, 0, "no text for an empty read");
    assert_eq!(texts.read(&mut open, 4, Some(0)), "text");
    assert_eq!(texts.read(&mut open, 0, None), "");
    assert_eq!(open.read_pos, 4, "the empty read at 0 did not continue");
    assert_eq!(texts.read(&mut open, 6, None), "text 2");
}

/// A read whose bytes cannot be delivered moves nothing: the next read
/// serves them from the same text.
#[test]
fn an_undelivered_read_moves_nothing() {
    let mut texts = Texts(0);
    let mut open = opened();
    let refused = texts.read_into(&mut open, 4, None, &mut |_| Err(crate::EFAULT));
    assert_eq!(refused, Err(crate::EFAULT));
    assert_eq!(open.pos, 0);
    assert_eq!(texts.read(&mut open, 6, None), "text 1");
    assert_eq!(texts.0, 1, "the text made for the failed read is served");
}

/// Two reads of one description, the second run while the first made its
/// text: the first takes the position as it is when it serves, so the two
/// read consecutive bytes, never the same ones.
#[test]
fn a_read_takes_the_position_when_it_serves() {
    let mut texts = Texts(0);
    let mut open = opened();
    let mut first = None;
    assert_eq!(
        open.read_step(&mut first, 1, None, &mut |_| Ok(())),
        Ok(None)
    );
    first = Some(texts.made());
    // Another thread's whole read runs meanwhile.
    assert_eq!(texts.read(&mut open, 1, None), "t");
    let served = open
        .read_step(&mut first, 1, None, &mut |_| Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(served, b"e");
    assert_eq!(open.pos, 2);
}

/// `name_to_int`: decimal digits with no leading zero, within an `int`.
#[test]
fn process_names_are_canonical_decimal_pids() {
    assert_eq!(pid_name("1"), Some(1));
    assert_eq!(pid_name("0"), Some(0));
    assert_eq!(pid_name(&i32::MAX.to_string()), Some(i32::MAX));
    for name in ["", "01", "+1", "-1", "1a", " 1"] {
        assert_eq!(pid_name(name), None, "{name:?}");
    }
    assert_eq!(pid_name(&(i64::from(i32::MAX) + 1).to_string()), None);
}

/// Every listed entry looks up to the node it was listed as, its path names
/// it, and its kind and inode are its metadata's; the machine's files come
/// in `proc_match`'s order, then `self`, then the processes by pid.
#[test]
fn the_root_lists_what_its_lookups_find() {
    let entries = listing(Node::Root);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names[..2], [".", ".."]);
    let self_at = names.iter().position(|name| *name == "self").unwrap();
    let files = &names[2..self_at];
    let ordered = |a: &str, b: &str| (a.len(), a.as_bytes()) < (b.len(), b.as_bytes());
    assert!(
        files.windows(2).all(|pair| ordered(pair[0], pair[1])),
        "{files:?}"
    );
    let pids: Vec<i32> = names[self_at + 1..]
        .iter()
        .map(|name| pid_name(name).unwrap())
        .collect();
    assert!(pids.windows(2).all(|pair| pair[0] < pair[1]), "{pids:?}");
    assert!(pids.contains(&Process::INIT.pid()));
    assert!(pids.contains(&me()));
    let mut inodes: Vec<u64> = Vec::new();
    for entry in &entries[2..] {
        let node = lookup(Node::Root, &entry.name).unwrap();
        assert_eq!(node_at(&node.path()), Some(node));
        assert_eq!(node.kind(), entry.kind);
        assert_eq!(node.ino(), entry.ino);
        inodes.push(entry.ino);
        if node.is_directory() {
            for inner in &listing(node)[2..] {
                let file = lookup(node, &inner.name).unwrap();
                assert_eq!(node_at(&file.path()), Some(file));
                assert_eq!(file.ino(), inner.ino);
                inodes.push(inner.ino);
            }
        }
    }
    let count = inodes.len();
    inodes.sort_unstable();
    inodes.dedup();
    assert_eq!(inodes.len(), count, "distinct inodes");
    assert_eq!(lookup(Node::Root, "nosuch"), Err(ENOENT));
    assert_eq!(lookup(Node::Root, "01"), Err(ENOENT));
    assert_eq!(lookup(Node::Machine(Machine::Uptime), "x"), Err(ENOTDIR));
}

fn walked(start: Node, path: &str, nofollow: bool, no_symlinks: bool) -> Result<Walked, c_int> {
    let mut remaining: VecDeque<String> = path
        .split('/')
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    walk(start, &mut remaining, nofollow, no_symlinks, &mut 0)
}

fn me() -> i32 {
    Process::current().pid()
}

/// `self` is followed but as a final component under `nofollow`, and never
/// under `no_symlinks`; `..` climbs to the root and out of it; nothing is
/// found through a file.
#[test]
fn a_walk_follows_self_and_leaves_by_dot_dot() {
    let at = |node| Ok(Walked::At(node));
    assert_eq!(
        walked(Node::Root, "self", false, false),
        at(Node::Process(me()))
    );
    assert_eq!(walked(Node::Root, "self", true, false), at(Node::SelfLink));
    assert_eq!(
        walked(Node::Root, "self/stat", true, false),
        at(Node::Of(me(), OfProcess::Stat))
    );
    assert_eq!(walked(Node::Root, "self", false, true), Err(ELOOP));
    assert_eq!(
        walked(Node::Root, "self/./..", false, false),
        at(Node::Root)
    );
    assert_eq!(
        walked(Node::Root, "self/../..", false, false),
        Ok(Walked::Left)
    );
    assert_eq!(walked(Node::Root, "uptime/x", false, false), Err(ENOTDIR));
    assert_eq!(link_target(Node::SelfLink), Some(me().to_string()));
    assert_eq!(link_target(Node::NetLink).as_deref(), Some("self/net"));
    assert_eq!(link_target(Node::Root), None);
}

/// A process's `task` directory lists its live threads by id, each a
/// directory of that thread's files; `..` climbs back through them, and an
/// id no live thread has is `ENOENT`.
#[test]
fn a_process_lists_its_threads_under_task() {
    let at = |node| Ok(Walked::At(node));
    let tasks = Node::Tasks(me());
    assert_eq!(walked(Node::Root, "self/task", false, false), at(tasks));
    assert_eq!(
        walked(
            Node::Root,
            &format!("self/task/{}/stat", me()),
            false,
            false
        ),
        at(Node::OfThread(me(), me(), OfProcess::Stat))
    );
    assert_eq!(
        walked(
            Node::Root,
            &format!("self/task/{}/../..", me()),
            false,
            false
        ),
        at(Node::Process(me()))
    );
    let entries = listing(tasks);
    assert_eq!(entries[1].ino, Node::Process(me()).ino());
    let tids: Vec<i32> = entries[2..]
        .iter()
        .map(|entry| pid_name(&entry.name).unwrap())
        .collect();
    assert!(tids.contains(&me()), "{tids:?}");
    assert!(tids.windows(2).all(|pair| pair[0] < pair[1]), "{tids:?}");
    for tid in tids {
        let thread = lookup(tasks, &tid.to_string()).unwrap();
        assert_eq!(thread, Node::Thread(me(), tid));
        assert_eq!(node_at(&thread.path()), Some(thread));
        let files: Vec<String> = listing(thread)[2..]
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        for name in files {
            let file = lookup(thread, &name).unwrap();
            assert_eq!(walked(file, "..", false, false), Err(ENOTDIR));
            assert_eq!(file.parent(), thread);
        }
    }
    assert_eq!(lookup(tasks, &i32::MAX.to_string()), Err(ENOENT));
    let init = Node::Tasks(Process::INIT.pid());
    let init_tids: Vec<String> = listing(init)[2..]
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    assert_eq!(init_tids, [Process::INIT.pid().to_string()]);
}

/// `net` is followed to the caller's `net` directory, whose `..` is the
/// process's; its tables come in `proc_match`'s order and look up to what
/// is listed, each one header line at the width its `seq_show` pads to.
#[test]
fn net_leads_to_the_callers_socket_tables() {
    let at = |node| Ok(Walked::At(node));
    let net = Node::Net(me());
    assert_eq!(walked(Node::Root, "net", false, false), at(net));
    assert_eq!(walked(Node::Root, "net", true, false), at(Node::NetLink));
    assert_eq!(
        walked(Node::Root, "net/tcp", true, false),
        at(Node::NetFile(me(), NetFile::Tcp))
    );
    assert_eq!(
        walked(Node::Root, "net/..", false, false),
        at(Node::Process(me()))
    );
    assert_eq!(
        walked(Node::Root, "net/../..", false, false),
        at(Node::Root)
    );
    assert_eq!(walked(Node::Root, "net", false, true), Err(ELOOP));
    assert_eq!(
        walked(Node::Root, &format!("{}/net", me()), false, false),
        at(net)
    );
    let entries = listing(net);
    assert_eq!(entries[1].ino, Node::Process(me()).ino());
    let names: Vec<&str> = entries[2..]
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    let ordered = |a: &str, b: &str| (a.len(), a.as_bytes()) < (b.len(), b.as_bytes());
    assert!(
        names.windows(2).all(|pair| ordered(pair[0], pair[1])),
        "{names:?}"
    );
    for entry in &entries[2..] {
        let Ok(Node::NetFile(pid, file)) = lookup(net, &entry.name) else {
            panic!("{} is no table", entry.name);
        };
        assert_eq!(pid, me());
        assert_eq!(
            node_at(&Node::NetFile(pid, file).path()),
            Some(Node::NetFile(pid, file))
        );
        let header = net::header(file);
        let lines = header.split_inclusive(|byte| *byte == b'\n').count();
        assert_eq!(lines, 1, "{}", entry.name);
        assert!(header.ends_with(b"\n"));
        let padded = match file {
            NetFile::Tcp => Some(150),
            NetFile::Udp => Some(128),
            NetFile::Tcp6 | NetFile::Udp6 | NetFile::Unix => None,
        };
        if let Some(len) = padded {
            assert_eq!(header.len(), len, "{}", entry.name);
        } else {
            assert_ne!(header[header.len() - 2], b' ', "{}", entry.name);
        }
    }
}

/// Every directory's link count is two plus the directories it lists, as
/// `pid_entry_nlink` and `proc_root_getattr` count them.
#[test]
fn a_directory_links_the_directories_it_lists() {
    let mut directories = vec![Node::Root];
    while let Some(dir) = directories.pop() {
        let listed: Vec<Node> = listing(dir)[2..]
            .iter()
            .filter(|entry| entry.kind == FsEntryKind::Directory)
            .map(|entry| lookup(dir, &entry.name).unwrap())
            .collect();
        assert_eq!(
            metadata(dir).nlink as usize,
            2 + listed.len(),
            "{}",
            dir.path()
        );
        directories.extend(listed);
    }
}
