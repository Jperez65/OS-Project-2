# OS-Project-2

1. Multi-Threading (Parallelizing Password Processing)

Before: Single-Threaded Execution
The original code processes one password at a time.
It reads a password from pass_list, computes hashes for that password, checks each computed hash 
against all stored hashes, and stores a match if found. This is sequential and only runs on one CPU core.

After: Multi-Threaded Execution
The optimized code creates 8 worker threads that process passwords in parallel.
Each thread grabs the next available password dynamically, computes hashes and checks for matches,
and updates the shared cracked list if a match is found. Why is this faster?
Parallel processing: 8 threads run at the same time instead of just 1.
Full CPU Utilization: Uses all available CPU cores, dramatically reducing runtime.

2. Direct Binary Hash Comparison Instead of Hex Conversions

Before: String-Based Hash Storage and Comparison
Hashes are stored as hexadecimal strings (e.g., "5f4dcc3b5aa765d61d8327deb882cf99").
Every computed hash is converted from binary to hex (sprintf). The comparison is done using string
comparison (strcmp).

After: Direct Binary Storage and Comparison
Hashes are stored as binary arrays (raw 16-byte representation).
Instead of converting computed hashes to hex,binary hashes are directly compared using memcmp().
Why is this faster? sprintf() is slow → Avoiding it removes unnecessary computation.
memcmp() is significantly faster than strcmp() because it operates on raw bytes instead of 
parsing character-by-character, it stops immediately when a mismatch is found, and
binary storage reduces memory footprint and improves cache efficiency.

3. Single-Pass File Reading with Dynamic Allocation

Before: Two-Pass File Reading
Reads the hashed_list file twice: First pass: Count the number of hashes. Second pass: Read and 
store the hashes in memory.

After: Single-Pass File Reading
Reads each file once using a dynamic array that grows as needed. Starts with a small array (10 entries).
Expands dynamically using realloc() if more space is needed. Why is this faster?
Eliminates unnecessary file I/O → File reading is one of the slowest operations.
Avoids rewind() calls, reducing system overhead. Only reads each password/hash once, reducing memory 
bandwidth usage.

4. Dynamic Work Distribution Instead of Static Assignment
Before: Static Processing Order
Every password is processed in sequential order.
Some passwords take longer to process (e.g., longer passwords, different hash complexities).
Some passwords don’t match anything, wasting computation.

After: Dynamic Work Distribution
Uses a global work index (work_index). Each thread grabs the next available password.
Threads do not idle waiting for others to finish. Balanced workload avoids one thread 
doing more work than another. Why is this faster?
Eliminates thread imbalance → No idle threads waiting for others.
Ensures all CPU cores are working efficiently at all times.