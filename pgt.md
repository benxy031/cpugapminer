# PGT vs Submit Flow

```text
                 +----------------------+
                 |     mining loop      |
                 +----------+-----------+
                            |
                            v
                 +----------------------+
                 | sieve / scan pairs   |
                 +----------+-----------+
                            |
                            v
                 +----------------------+
                 |   gap found?         |
                 +----+-----------+-----+
                      | no        | yes
                      |           |
                      v           v
               +-------------+   +--------------------+
               | keep mining |   | update best gap    |
               +-------------+   +---------+----------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
           +--------------------+                      +--------------------+
           | submitted++        |                      |  PGT observer      |
           | accepted++ if ok   |                      +---------+----------+
           +--------------------+                                |
                                                                  v
                                                        +-------------------+
                                                        | rec++             |
                                                        | compare thresholds|
                                                        +----+----+----+----+
                                                             |    |    |
                                                             v    v    v
                                                     above_trend  above_cramer
                                                     above_submit
```

Poenta:
- `submitted` prati submit tok.
- `rec` prati novi best-gap record tok.
- Zato `submitted` i `rec` nisu isti broj.
- `above_submit` je najkorisniji mining signal jer pokazuje koliko je record gap prešao submit prag.
