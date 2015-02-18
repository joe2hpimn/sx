CREATE TABLE blocks(
    id INTEGER PRIMARY KEY,
    hash BLOB(20) NOT NULL,
    blockno INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(hash)
);

-- op=-1: DELETE, op=1: UPLOAD or RESERVE

CREATE TABLE token_ops(
    tokens_id BLOB(20) NOT NULL,
    op INTEGER NOT NULL,
    age INTEGER NOT NULL,
    PRIMARY KEY(tokens_id, op)
);
-- needed by GC
CREATE INDEX tokens_op ON token_ops(op, tokens_id, age);

CREATE TABLE reservations(
    reservations_id BLOB(20) NOT NULL,
    tokens_id BLOB(20) NOT NULL,
    ttl INTEGER NOT NULL,
    PRIMARY KEY (reservations_id, tokens_id)
);
-- needed by rebalance
CREATE INDEX reserve_tokens ON reservations(tokens_id, reservations_id);
-- needed by GC (not critical)
CREATE INDEX reserve_ttl ON reservations(ttl, tokens_id);

CREATE TABLE token_blocks(
    tokens_id BLOB(20) NOT NULL,
    blocks_hash BLOB(20) NOT NULL,
    age INTEGER NOT NULL,
    replica INTEGER NOT NULL,
    PRIMARY KEY(tokens_id, blocks_hash, age)
);
CREATE INDEX revmap ON token_blocks(blocks_hash, tokens_id, age);

SELECT "add_token:";
EXPLAIN QUERY PLAN INSERT OR IGNORE INTO token_ops(tokens_id, op, age) VALUES(:tokens_id, :op, :age);
SELECT "moduse:";
EXPLAIN QUERY PLAN INSERT OR IGNORE INTO token_blocks(tokens_id, blocks_hash, age, replica) VALUES(:tokens_id, :hash, :age, :replica);
SELECT "reserve:";
EXPLAIN QUERY PLAN INSERT INTO reservations(reservations_id, tokens_id, ttl) VALUES(:reserveid, :tokens_id, :ttl);
SELECT "get_meta";
EXPLAIN QUERY PLAN SELECT tokens_id, op FROM token_blocks NATURAL INNER JOIN token_ops NATURAL LEFT JOIN reservations WHERE blocks_hash=:hash AND age < :current_age AND reservations_id IS NULL;
SELECT "rit.q";
EXPLAIN QUERY PLAN SELECT id, hash FROM  blocks WHERE hash > :prevhash AND blockno IS NOT NULL;
SELECT "del_reserve";
EXPLAIN QUERY PLAN DELETE FROM reservations WHERE reservations_id=:reserveid;
SELECT "find_unused_token:";
EXPLAIN QUERY PLAN SELECT tokens_id FROM token_ops WHERE tokens_id IN (SELECT tokens_id FROM token_ops WHERE op <= 0 AND age <= :age AND tokens_id > :last_tokens_id) GROUP BY tokens_id HAVING SUM(op)=0 ORDER BY tokens_id LIMIT 1;
SELECT "find_unused_block:";
EXPLAIN QUERY PLAN SELECT id, blockno, hash FROM blocks LEFT JOIN token_blocks ON blocks.hash=blocks_hash WHERE id > :last AND tokens_id IS NULL ORDER BY id;
SELECT "delete_old:";
EXPLAIN QUERY PLAN DELETE FROM token_blocks WHERE blocks_hash=:hash AND age < :current_age;
SELECT "find_expired_reservation:";
EXPLAIN QUERY PLAN SELECT reservations_id, tokens_id FROM reservations NATURAL INNER JOIN token_blocks INNER JOIN blocks ON blocks.hash = blocks_hash WHERE reservations_id > :lastreserveid GROUP BY reservations_id HAVING created_at < :expires ORDER BY reservations_id LIMIT 1;
SELECT "find_expired_reservation2:";
EXPLAIN QUERY PLAN SELECT tokens_id FROM reservations WHERE ttl < :now LIMIT 1;
SELECT "gc_token_blocks:";
EXPLAIN QUERY PLAN DELETE FROM token_blocks WHERE tokens_id=:tokens_id;
SELECT "gc_token:";
EXPLAIN QUERY PLAN DELETE FROM token_ops WHERE tokens_id=:tokens_id;
