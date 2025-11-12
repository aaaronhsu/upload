# Lab 3 - RDMA

CompSci 514/ECE 558 Advanced Computer Networks, Fall 2025

## Introduction

This lab is intended to familiarize you with basic RDMA workflow. You will complete the implementation of a file sender `rdma_client` that exchanges messages with the receiver `rdma_server` and sends a file over RDMA. We will provide a skeleton code for you to fill in important RDMA functions, however you are allowed to modify any code as long as it follows the protocol and works with the provided receiver executable.

## Setup

- Operating system: Ubuntu 22.04 or later
- Programming language: C

You will need to setup two QEMU virtual machines and use Soft-RoCE to simulate the RDMA network.

<details>
<summary>Click to expand</summary>

Please refer to [setup.pdf](https://courses.cs.duke.edu/fall25/compsci514/syllabus.html) for this step.

</details>

## Building and compiling your code

To compile your source code into binaries, run

```
duke@vcm-59487$ cmake .
duke@vcm-59487$ make
```

The executables should be in `bin/`. Copy (we recommend `sftp`) `rdma_server` to VM1 and `rdma_client` to VM2, and change their mode (we recommend `chmod u+x`) so that you can execute them.

### Run the server on VM1

```
student@vm1$ ./bin/rdma_server
Server is listening successfully at: 0.0.0.0 , port: 20886
...
Server shut-down is complete
student@vm1$
```

### And then run your client on VM2

You can transfer an arbitrary file. We recommend `rdma_client` for simplicity.

```
student@vm2$ ./bin/rdma_client -a <vm1_ip_address> -f <filename> -i <your-netid>
...
Client: salted hash = fc5adc...c20
...
student@vm2$
```

## Submission

You need to submit two things on Gradescope:

- Your source code, all of your `*.c` and `*.h` files, including the ones provided and the ones you wrote
- Your NetID and the salted hash your client receives
