# misc

Initial attempts to develop `kmodleak` using `bpftrace` and `BCC` Python.

## Limitations

  - `bpftrace`: No way to iterate over stack frames to filter events in-kernel.
  
  - `BCC`: Hit jump limit when iterating over the stack. Refused to do
    function-by-function verification (even though libbpf version ultimately
    didn't require f.b.f. verification).
