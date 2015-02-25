CREATE TABLE blocks(
    id INTEGER PRIMARY KEY,
    hash BLOB(20) NOT NULL,
    blockno INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(hash)
);

-- op=-1: DELETE, op=1: UPLOAD or RESERVE

CREATE TABLE revision_ops(
    revision_id BLOB(20) NOT NULL,
    op INTEGER NOT NULL,
    age INTEGER NOT NULL,
    PRIMARY KEY(revision_id, op)
);
-- needed by GC
CREATE INDEX idx_op_revision ON revision_ops(op, revision_id, age);

CREATE TABLE reservations(
    reservations_id BLOB(20) NOT NULL,
    revision_id BLOB(20) NOT NULL,
    ttl INTEGER NOT NULL,
    PRIMARY KEY (reservations_id, revision_id)
);
-- needed by rebalance
CREATE INDEX reserve_tokens ON reservations(revision_id, reservations_id);
-- needed by GC (not critical)
CREATE INDEX reserve_ttl ON reservations(ttl, revision_id);

CREATE TABLE revision_blocks(
    revision_id BLOB(20) NOT NULL,
    blocks_hash BLOB(20) NOT NULL,
    age INTEGER NOT NULL,
    replica INTEGER NOT NULL,
    PRIMARY KEY(revision_id, blocks_hash, age)
);
CREATE INDEX revmap ON revision_blocks(blocks_hash, revision_id, age);

SELECT "add_token:";
EXPLAIN QUERY PLAN INSERT OR IGNORE INTO revision_ops(revision_id, op, age) VALUES(:revision_id, :op, :age);
SELECT "moduse:";
EXPLAIN QUERY PLAN INSERT OR IGNORE INTO revision_blocks(revision_id, blocks_hash, age, replica) VALUES(:revision_id, :hash, :age, :replica);
SELECT "reserve:";
EXPLAIN QUERY PLAN INSERT INTO reservations(reservations_id, revision_id, ttl) VALUES(:reserveid, :revision_id, :ttl);
SELECT "get_meta";
EXPLAIN QUERY PLAN SELECT revision_id, op FROM revision_blocks NATURAL INNER JOIN revision_ops NATURAL LEFT JOIN reservations WHERE blocks_hash=:hash AND age < :current_age AND reservations_id IS NULL;
SELECT "rit.q";
EXPLAIN QUERY PLAN SELECT id, hash FROM  blocks WHERE hash > :prevhash AND blockno IS NOT NULL;
SELECT "del_reserve";
EXPLAIN QUERY PLAN DELETE FROM reservations WHERE reservations_id=:reserveid;
SELECT "find_unused_token:";
EXPLAIN QUERY PLAN SELECT revision_id FROM revision_ops WHERE revision_id IN (SELECT revision_id FROM revision_ops WHERE op <= 0 AND age <= :age AND revision_id > :last_revision_id) GROUP BY revision_id HAVING SUM(op)=0 ORDER BY revision_id LIMIT 1;
SELECT "find_unused_block:";
EXPLAIN QUERY PLAN SELECT id, blockno, hash FROM blocks LEFT JOIN revision_blocks ON blocks.hash=blocks_hash WHERE id > :last AND revision_id IS NULL ORDER BY id;
SELECT "delete_old:";
EXPLAIN QUERY PLAN DELETE FROM revision_blocks WHERE blocks_hash=:hash AND age < :current_age;
SELECT "find_expired_reservation:";
EXPLAIN QUERY PLAN SELECT reservations_id, revision_id FROM reservations NATURAL INNER JOIN revision_blocks INNER JOIN blocks ON blocks.hash = blocks_hash WHERE reservations_id > :lastreserveid GROUP BY reservations_id HAVING created_at < :expires ORDER BY reservations_id LIMIT 1;
SELECT "find_expired_reservation2:";
EXPLAIN QUERY PLAN SELECT revision_id FROM reservations WHERE ttl < :now LIMIT 1;
SELECT "gc_revision_blocks:";
EXPLAIN QUERY PLAN DELETE FROM revision_blocks WHERE revision_id=:revision_id;
SELECT "gc_token:";
EXPLAIN QUERY PLAN DELETE FROM revision_ops WHERE revision_id=:revision_id;

SELECT "::::";
EXPLAIN QUERY PLAN SELECT replica, op, revision_id FROM revision_blocks NATURAL INNER JOIN revision_ops NATURAL LEFT JOIN reservations WHERE blocks_hash=:hash AND age < :current_age AND reservations_id IS NULL;
