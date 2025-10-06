# SC3010 Computer Security

## Topics

-   Introduction
-   Basics of Cyber Security
-   Software Security 1
-   Software Security 2
-   Software Security 3
-   Operating System Security 1
-   Operating System Security 2
-   SingHealth Data Breach

## Introduction

-   Computer security guarantees the correct usage of computer systems and desired properties in the presence of malicious entities
-   Critical to physical safety
    -   Power grids and water systems can cause blackouts, water contamination or disruption of supply
    -   Transportation networks and connected vehicles can cause collisions and jams
    -   Medical devices can pose life-threatening risks to patients
-   Critical to personal privacy
    -   Database breaches compromises personal data and credentials
    -   Ransomware encrypts personal files and demand payment for release
    -   Spyware remotely monitor user activity
-   Critical to national security
    -   Cyber espionage can lead to classified information being passed to rival government
    -   Election interference can have false information being spread to influence public opinion or manipulate voting systems
    -   Cyber wafare disrupts military operations and infrastructure
    -   Cyber terrorism where attacks are launched to cause physical destruction
-   System complexity can lead to insecurity
    -   From a user perspective, security features might not be configured correctly and users like convenience, may try to disable some security configurations
    -   From a developer perspective, security features are not designed correctly and they’re humans afterall, can make mistakes
    -   From a external perspective, individual’s trust can be manipulated and social engineered

## Basics of Cyber Security

### Threat Model

-   Used to describe adversaries and threats in consideration
-   Identify trusted and what untrusted components (TCB)
    -   For untrusted entities
        -   Outline the resources, capabilities, and knowledge
        -   Define the actions that untrusted entities can perform within the system
    -   Specify the security properties the system aims to achieve

### Trust

-   **Degree to which an entity is expected to behave**
    -   Examples of expected behaviour
        -   Anti-malware can detect malicious program
        -   System can prevent illegal login
    -   Examples of unexpected behaviour
        -   Website exposing private data to third parties
        -   Application injecting virus into a system
-   **Security cannot be established if no entities are trusted**

### Trusted Computing Base (TCB)

-   **Set of components that need to be trusted to ensure security of cyber system**
    -   Components include OS, firmware, hardware and more
    -   Components outside of TCB can be malicious and misbehave
-   When designing security solution
    -   **Assume all components inside TCB are secure with valid justifications**
    -   Prevent any damages from components outside TCB

#### Design Principles

-   Unbypassable where there must be no way to breach the system security by bypassing TCB (completeness)
-   Tamper-resistant where TCB should be protected against other parts outside of TCB and cannot modify TCB code or state (security)
-   Verifiable where it should be possible to verify correctness of TCB (correctness)
-   Follow KISS principle and have small TCB for easier verification and trustworthiness

### Attacker Assumption

-   Active attackers manipulate or disrupt systems by modifying data or injecting code
-   Passive attackers observe and gather information without interferring system
-   Attacker is generally aware of system design and architecture but lack detailed knowledge and must probe deeper using trial and error
-   Maybe be constrained by computing resource, time and parts of system that cannot be accessed directly

### Security Properties

-   Using the CIA model
    -   Confidentiality (from data reading) prevents unauthorized disclosure of information
    -   Integrity (from data writing) prevents unauhtorized modification of information, mainly caused by active attacker
    -   Availability prevents unauthorized witholding of information
-   Other properties
    -   Accountability ensures actions of entity can be traced and identified
    -   Non-repudiation ensures unforgeable evidence that specifies actions occured
    -   Authenticity ensure the comunicated entity is the correct entity
    -   Anonymity hides personal information and identity from being leaked
    -   Verifiability ensures system operations can be independently verified
    -   Freshness ensures data or communications are current and not reused
    -   Fault tolereance ensures system can continue to function correctly despite failures

### Security Strategies

-   Prevention by taking measures that prevent system from being damanged
-   Detection by taking measures to detect when, how, and by whom system was damaged by
-   Reaction by taking measures to recover system form damage and assume worst-case scenarion to better prepare

### Design Principles

#### Least of Privilege

-   **Give each entity the minimal permissions to complete tasks**
-   Given privilege when needed and revoke when task is completed
-   Less privilege a program has, the less harm it can do
-   Examples
    -   Never perform personal activities using root user
    -   Photo editing application should only have access to the gallery and not microphone or location

#### Separation of Privilege

-   **To perform a privileged action, it requires multiple parties to work together to exercise the privilege**
-   Minimize risk of miuse by a single user and ensure no single entity has full control over critical processes
-   Examples
    -   Financial system where transferring large sums requiring approval from employee and manager
    -   Developer writing code that requires review from multiple teams before deployment

#### Defense in Depth

-   **Increase difficulty of attacking entire system by stacking defenses**
-   High implementation cost
-   Entire effectiveness if often less than sum of all defenses

#### Security through Obscurity

-   **Rely on secrecy or concealing details of a system or its components**
-   If attacker does not know how a system works, they are less likely to compromise it
-   Often regarded as insufficient and unreliable as it can be reverse-engineered
-   Examples
    -   Sensitive files can be hidden behind obscure URL without proper authentication, but attack can discover URL through guessing and web crawling
    -   Developer hides details of source code and vulnerabilities, but attackers can deobfuscate or analyze binary to discover vulnerabilities

#### Kerckhoff’s Principle and Shannon’s Maxim

-   “the enemy knows the system”
-   Security of a system should not depend on secrecy of its design or algorithms
-   Always asssume attacker knows every detail about the system inside out
    -   This ensures systems are even more resilient given the design or implementation becomes public

## Software Security 1

-   Vulnerability is a weakness which allows an attacker to reduce the system’s information assurance
-   Exploit is a technique that takes advantage of a vulnerability and used by attacker on the system
-   Payload is the custom code that the attacker wants the system to execute

### Vulnerabilities

-   Memory safety violations
    -   Buffer overflow and over-reads
    -   Dangling pointers
-   Input validation errors
    -   Format string attacks
    -   SQL injection
    -   Code injection
    -   Cross-site scripting
-   Race conditions
    -   Time-of-check-to-time-of-use bugs
    -   Symlink races
-   Privilege confusion bugs
    -   Cross-site request forgery in web applications
    -   Clickjacking
    -   FTP bounce attack
-   Privilege escalation
-   Side-channel attack

#### Reason for Having Vulnerabilities

-   Human factor
    -   Programs are developed by human and people make mistakes
    -   Programmers are not security-aware
    -   Misconfigurations can lead to exploitation of software vulnerabilities
-   Language factor
    -   Some programming languages are not designed well for security
    -   Lack of strong typing
    -   Flexible handling of pointers and references
    -   Manual memory management leads to programming mistakes

### Malwares

-   Adware displays unwated advertisment
-   Ransomware block user’s data until ransom is paid
-   Spyware gather information about user and send it to attacker
-   Crimeware is designed specifically to automate cybercrime
-   Worms propagate to different computers without user intervention
-   Viruses propoagate to different computers and needs to be triggered by a user
-   Trojans pretend to do something useful but mask malicious behaviours
-   Rootkits obtain root privileges to compromise computer
-   Backdoor allow a remote party to gain access to a computer

### Memory Layout of a Program

-   The code section contains the program code
    -   Fixed size
    -   Read only
-   The static data section contains statically allocated data
    -   Variables
    -   Constant
-   The stack section contain parameters and local variables of method as they are invoked
    -   Each invocation of a method creates one frame which is pushed to the stack
    -   Grows to lower address
-   The heap section contains dynamically allocated data
    -   Data like class instances and arrays
    -   Grows to higher address

#### Stack

-   Store parameters, local variables and intermediate computation results
-   Usually subdividied into multiple frames
    -   When method invoked, new frame is pushed onto stack to store local variables and intermediate results
    -   When method exits, frame is popped, exposing the frame of its caller

#### Function Call Convetion

TBC

#### Inside a Frame for One Function

-   Contains 2 pointers
    -   EBP, base pointer, fixed at frame base
    -   ESP, stack pointer, is the current pointer in frame (current lowest value on the stack)
-   Frame consists of
    -   Function parameters
    -   Return address of caller function
    -   Base pointer of caller function
    -   Local variables
    -   Intermediate operands

### Common Vulnerability in C

-   String is an array of characters
    -   Must end with NULL or \o
    -   String of length n can hold only n-1 characters since last character is reserved for NULL
-   Other common vulnerabilities include
    -   `strcat(dest, src)` for appending string src to end of string dest
    -   `gets(str)` to read data from a standard input stream and store it into str
    -   `scanf(format)` to read formatted input from standard input stream
    -   `sprintf(str, format)` create strings with specified formats and store resulting string in str

#### Buffer Overflow

-   A buffer overflow happens when a program writes more data to a buffer than it hold
    -   Overwrites adjacet memory

##### Example

-   `strcpy()` copies a string from a source to destination
    -   Problem arises when source string is larger than destination string
    -   This means more data goes into the memory buffer than capacity allocated and overwriting other information adjacent to memory buffer
    -   C does not check boundaries when copying data to memory
    -   Vulnerability is widespread
    -   Can allow privilege escalation, bypass authentication, execute arbitrary command and more

#### Stack Smashing

-   Stack smashing specifically targets the stack by overwriting critical data, like the return address of a function
    -   By doing so, attackers can redirect program execution to malicious code that is often injected in the same input
-   Shellcode address can be hard to guess and incorrect address can cause system crash such as unmapped address, protected kernel code, data segmentation
    -   Improve the chance by inserting many NOP (No-Operation) instructions before shellcode

##### Example

-   Function declares a local buffer (`char name[16]`) on stack
-   Program copies user input into buffer without checking its size (using `strcpy()`)
-   Input of size 20 bytes is larger than buffer size overwrites adjacent stack data, including return address
-   Attackers include executable code (shellcode) in input
-   The return address is overwritten to point to the shellcode's location in memory
-   When function returns, program jumps to shellcode, running the attacker's code

## Software Security 2

### Format String Vulnerabilities

-   `printf` in C prints a format string to the screen
    -   Format string is a string with special format specifiers (escape sequences prefixed with %)
    -   Can take more than one argument where first argument is the format string and the rest consists of values to be substituted
    -   Examples
        -   printf(”Hello, world”)
        -   printf(”Year %d”, 2014)
        -   printf(”The value of pi: %f”, 3.14)
        -   printf(”The first character in %s is %c”. “abc”, ‘a’)
-   Escape sequences are essentially instructions

    ```c
    // unsafe
    #include <stdio.h>
    #include <string.h>
    int main(int argc, char* argv[]) {
        char user_input[100];
        scanf("%s", user_input);
        printf(user_input);
    }

    // safer
    #include <stdio.h>
    #include <string.h>
    int main(int argc, char* argv[]) {
        char user_input[100];
        scanf("%s", user_input);
        printf("%s\n", user_input);
    }
    ```

    -   Attack works by injecting escape sequences into format strings
    -   printf(user_input) treats user input as a format string, allowing attackers to use specifiers like %x, %s, or %n to leak memory, crash the program, or overwrite data
    -   scanf("%s", user_input) does not limit input length, risking overflow of the 100-byte user_input buffer

-   Must have more format specifiers than actual arguments in order to exploit format string vulnerability
    -   If there are more arguments than format specifiers, there's no vulnerability as extra arguments will be ignored by the stack

#### Leaking Information from Stack

```c
// correct function
printf(“x value: %d, y value: %d, z value: %d”, x, y, z);

// incorrect function
printf(“x value: %d, y value: %d, z value: %d”, x, y);
```

-   For correct function,
    -   Prints three variables (x, y, z) correctly
    -   `%d` format specifiers tell printf to expect three integer values, which are provided as x, y and z
-   For incorrect function,
    -   `printf` expects three integers (because of three %d specifiers), but only two (x and y) are provided
    -   Stack doesn't know an argument is missing, so printf grabs whatever random data is next on the stack as the third value
-   Danger
    -   Data that do not belong to user will be printed out from the stack

#### Crash the Program

```c
// correct function
printf("%s", "Hello, world")

// incorrect function
printf("%s")
```

-   For correct function,
    -   `%s`is a format specifier that tells printf to expect a string (a pointer to a sequence of characters)
    -   `Hello, World` is the string, and its memory address (a pointer) is pushed onto the stack as an argument for `printf`
    -   `printf` reads the pointer from the stack, finds the string in memory, and prints it correctly
-   For incorrect function,
    -   `printf` still looks for a string pointer on the stack, even though none was provided
    -   It grabs whatever random data is on the stack at the expected position
-   Danger
    -   Address can be invalidated and program will crash

#### Modify the Memory

```c
// correct function
printf("13579%n", &i)

// incorrect function
printf("13579%n")
```

-   For correct function,
    -   Format string `13579%n` tells `printf` to print `13579` (5 characters)
    -   Use `%n` to store the number of characters printed so far (5) into the memory address provided as an argument
    -   `&i` is the address of an integer variable `i`, passed as an argument and pushed onto the stack
    -   `printf` writes the number 5 (the count of characters printed) to the memory address `&i`, so `i` becomes 5
-   For incorrect function,
    -   For `%n`, it tries to write the number 5 (characters printed) to a memory address it expects on the stack
    -   Since no argument was provided, printf grabs a random value from the stack, treating it as a memory address
-   Danger
    -   Attackers can overwrite important program flags that control access privileges
    -   Attackers can overwrite return addresses on the stack, function pointers and more

#### Fixing Format String Vulnerability

-   Limit the ability of attackers to control format strings
    -   Hard-coding format strings (use `printf("%s\n", user_input)` instead of `printf(user_input)`)
    -   Do not use `%n`
    -   Compiler support to match `printf` arguments with format strings

### Integer Overflow Vulnerabilities

-   In mathematics, integers form an infinite set
-   In a computer, integers are repsented in binary
    -   To be specific a binary string of fixed length
    -   Hence there is a finite number of integers
-   Signed integers can be represented as 2’s complement
-   MSB indicates the sign of the integer
    -   0 for positive
    -   1 for negative
-   Overflow when an integer is increased over its maximal value or decreased below its minimal value
    -   Unsigned overflow is when binary representation cannot represent an integer value
    -   Signed overflow is when a value is carried over to the sign bit

#### Artihmetic Overflow

-   Happens when a calculation produces a result too large to fit in the memory space assigned to it

##### Example

-   4-bit integer can store numbers from 0 to 15
-   Adding 1 to 15 will result in 16
-   Overflows and wrapes around, resulting in 0 or incorrect value like -16 in signed integers

#### Bypass Length Checking

-   Must check for individual lengths and combined length to defend against buffer overruns

#### Widthness Overflow

-   Typically refers to issues when data is moved between variables of different sizes in memory, causing data loss or corruption

##### Example

-   Suppose having a 32-bit integer and storing it in a 16-bit integer
-   Gets truncated if number is too big
-   Very likely will end up with a wrong number stored

#### Truncation Errors

-   Bad type conversion can cause widthness overflows

#### Fixing Integer Overflow Vulnerability

-   Better length checking
-   Safe type conversion where converting from a type of smaller size to that or larger size

### Scripting Vulneralbilities

-   Scripting language is used to
    -   Construct commands from predefined code fragments and user input at runtime
    -   Script is then passed to another software component where it is executed
    -   Domain-specific language is used for a particular environment
-   Vulnerabilities
    -   Additional commands can be hidden in the user input
    -   System will execute malicious command without any awareness

#### Common Gateway Interface Script

```bash
# command running on server
cat $file | mail $clientaddress

# normal case
cat hello.txt | mail 127.0.0.1

# compromised input where attacker set $clientadress as something malicious
cat hello.txt | mail 127.0.0.1 | rm -rf /

```

-   CGI script is a standard way in which information may be passed to and from the browser and server

##### Defenses against Command Injection

-   Avoid shell commands
-   Use more secure APIs
    -   Python: `subprocess.run()`
    -   C: `execve()`
-   Input inspection
    -   Sanitize and remove dangerous characters
    -   Validate and reject malformed input
    -   Whitelist allowed values
-   Drop privileges
    -   Run process as non-root users

#### SQL Injection

```sql
SELECT * FROM client WHERE name = $name

# normal case
SELECT * FROM client WHERE name = 'bob'

# compromised input where attacker adds extra condition
# since 1=1 is always true, the entire database is returned
SELECT * FROM client WHERE name = 'bob' OR 1=1
```

##### Defenses against SQL Injection

-   Use parameterized queries
    -   Ensure user input is treated as data and not command
-   Use ORM
    -   Abstract SQL generation and reduce risk of generation
-   Input inspection
    -   Sanitize and remove dangerous characters
    -   Validate and reject malformed input
    -   Whitelist allowed values

#### Cross Site Scripting (XSS)

-   Targets web application that may require users to provide input
-   Vulnerabilities
    -   Malicious user may encode executable content in input which can be echoed back in a webpage
    -   Victim later visits the web page and his web browser may execute malicious commands on his computer

#### Stored XSS (Persistent)

-   Attacker discovers a XSS vulnerability in a website
-   Attacker embeds malicious commands inside input and sends it to website
-   Now the command has been injected to the website
-   Victim then browses the website and malicious command will run on the victim’s computer

#### Reflected XSS (Non-persistent)

-   Attacker discovers a XSS vulnerability in a website
-   Attacker creates a link with malicious commands inside
-   Attacker distribute link to victims
-   Victim clicks on link and malicious commands get activated

##### Defenses against Cross Site Scripting

-   Use Content Security Policy (CSP)
    -   Instruct browser to only use resources loaded from specific places
    -   Policies are enforced by browser
        -   Disallow all inline scripts
        -   Only allowing scripts from specific domains
-   Input inspection
    -   Sanitize and remove dangerous characters
    -   Validate and reject malformed input

## Software Security 3

### Safe Programming

-   Unsafe C library functions that have no range checking
    ```c
    strcpy (char *dest, char *src)
    strcat (char *dest, char *src)
    gets (char *s)
    ```
-   Safer versions
    ```c
    strncpy (char *dest, char *src, int n)
    strncat (char *dest, char *src, int n)
    fgets(char *BUF, int N, FILE *FP);
    ```
    -   `strncpy()` adds another parameter to indicate intended length of intended characters to copy from source to destination
        -   If n is less than the length of `src` (excluding \0), `dest` won't be null-terminated, which can cause problems when using `dest` as a string
        -   Always ensure `dest` has enough space for n characters (and ideally an extra slot for \0)
            -   `strncpy()` does not automatically add terminator at the end
            -   Though `strcpy()` adds a terminator
        -   If n is greater than or equal to the length of `src` (including its \0), the null terminator is copied, and no manual addition is needed

#### Safe Libraries

-   libsafe
    -   Check some common traditional C functions
        -   Examine current stack and frame pointers
        -   Denies attempts to write data to stack that overwrite return address or parameters
-   glib.h
    -   Provides Gstring type for dynamically growing null-terminated strings in C
-   Strsafe.h
    -   A new set of string-handling functions for C and C++
    -   Guarantees null-termination and always takees destination size as argument
-   SafeStr
    -   Provides new, high-level data type for strings, tracks accounting info for strings
    -   Performs many other operations
-   Glib
    -   Resizable and bounded
-   Apache portable runtime
    -   Resizable and bounded

#### Safe Language

-   Strong type
-   Always a trade-off between flexibility and security
-   Ada, Perl, Python, Java, C#, Visual Basic all have automatic bounds checking and do no not have direct memory access
-   Rust
    -   Designed to be a safe, concurrent and practical
    -   Supports functional and imperative-procedural paradigms
    -   Does not permit null pointers, dangling pointers or data races
    -   Memory and other resources are managed through RAII
-   Go
    -   Type safe, garbage-collected but C-looking lanugage
    -   Good concurrency model for taking advantage of multi-core machines
    -   Appropriate for server architectures

### Software Testing

#### Manual Code Reviews

-   Peer review is important before deployment
    -   Check for wrong use of data
        -   Variables not initialized
        -   Dangling pointers
        -   Array index out of bounds
    -   Faults in delcarations
        -   Undeclared variable
        -   Double declaration
    -   Faults in computation
        -   Division by zero,
        -   Mixed-type expressions
    -   Faults in relational expressions
        -   Incorrect boolean operator
        -   Wrong operator priorities
    -   Faults in control flow
        -   Infinite loops
        -   Loops that execute n-1 or n+1 times instead of n

#### Software Tests

-   Unit tests can be written to test individual components or functions of software in isolation
    -   Should cover all code including error handling
-   Regression tests can be written to test that new code changes to do negatively affect existing functionality
    -   Verify that software continues to function correctly after updates
-   Integration tests can be written to test interaction between multiple software modules or systems
    -   Enssure components work together as expected

#### Static Analysis

-   Analayze source code or binary before running it during compilation
    -   Explore all possible execution consequences with all possible input
    -   Approximate possible states
    -   Identify issues during development and reduces cost of fixing vulnerability
    -   Relies on predefined rules or policies to identify patterns of insecure coding practice
-   Limations
    -   May produce false positives requiring manual review
    -   Cannot detect runtime issues

#### Dynamic Analysis — Penetration Testing

-   Mainly use tools to generate effective test cases
-   Proactive security methods are used
    -   Simulate attacks on a system to identify weakness that is exploitable
    -   Goal is to identify vulenrabilites before attackers do
    -   Ensure compliacne wuth security regulations and improve the overall security postuer of systems and applications
-   General procedure
    -   Test system with tools
    -   Intepret testing results
    -   Checking exploitability
        -   Develop exploit or go back to first step

#### Dynamic Analysis — Fuzzing

-   Automated and scalable approach to test software at runtime
    -   Bombard program with random, corrupted or unexpeted data to identify how it behanves under unexpected conditions
    -   Observe program for crashes, memory issues or unexpected behaviours
    -   Examine failures to determine if they represent exploitable vulneratbilites
-   Limitations
    -   Limited code coverage
    -   Require expert analysis to assess whether system crashes are exploitable
    -   May miss logic flaws that do not result in crashes
-   Types of fuzzing
    -   Mutation-based
        -   Collects a corpus of inputs that explores as many states as possible
        -   Perturbe inputs randomly (bit flips, integer increments, substitute with small, large, negative integers) and possibly guided by heuristics
        -   Simple to set up and can be used for off-the-shelf software
    -   Generation-based
        -   Convert a specification of input format into a generative procedure
        -   Generate test cases according to procedure with pertubations
        -   Get higher coverage by leveraging knowledge of input format
        -   Requires a lot of effort to setup and domain specific
    -   Coverage-guided
        -   Using tradiontal fuzzing strategies to create new test cases
        -   Test program and measure code coverage
        -   Using code coverage as feedback to craft input for uncovered code
        -   Good at finding new states and combine well with other solutions

### Compiler and System Support

#### Address Space Layout Randomization

-   Put segment of each memory region (data, code, stack, heap) in a random locatioon every time program is launched
-   Harder for attacker to get address of malicious function
-   Within each segment, relative addresses are the same
-   No performance overhead
-   Deployed in mainstream systems (Linux, Android, iOS, Windows)
-   However, attackers can still get the base address of a stack
    -   Since addresses within the stack are normally fixed, attacker can compute addresses of any data in the stack
    -   Attacker can use brute force method to guess base address
    -   Format string vulnerability allows attacker to print out base pointer from the stack

#### StackGuard

-   Makes it difficult for attackers to only modify return address without overwriting stack memory in front of return address
-   Steps
    -   Embed a canary word next to return address (EIP) on the stack whenever a function is called
        -   Canary value needs to be random and cannot be guessed by attacker
    -   When stack-buffer overflows into the funtion return address, canary has to be overwritten as well
    -   Every time the function returns, check whether the canary is value is changed
    -   If so, someone is possibly attacking the program with stack-buffer overflows and program will be aborted
-   Teminator canary is a specific type of canary value designed to be harder for attackers to bypass
    -   Uses special values that like null bytes or other string terminators
    -   Chosen because they can disrupt an attacker’s attempt to overwrite the stack with malicious data, as many string-handling functions stop processing when they encounter such terminators
-   However, attackers can still obtain the canary value which will be used to overwrite the canary in the stack without changing the value
    -   By using format string vulnerability, attacker can print out values in the stack
    -   Attacker can use brute-force method to guess canary as well
-   Attackers can also overwrite the canary without touching the canary
    -   Format string vulnerability allows attacker to write to any location in memory and no need to be consecutive with the buffer
    -   Heap overflows do not overwrite a stack canary

#### Shadow Stack

-   Keep a copy of the stack in memory
    -   On function call, push EIP to shadow stack
    -   On function return, check that top of the shadow stack is the same EIP on the stack
    -   If there is a difference, then terminate program
-   Requires support of hardware
    -   Intel CET
        -   New register SSP (Shadow Stack Pointer)

#### StackShield

-   GNU C compiler extension that protects return address
-   Separate control (return address) from the data
    -   On function call, copy EIP to a non-overflowable area
    -   On function return, return address is restored
    -   Even if the return address on the stack is altered, it has no effect since the original return address will be copied back before returned address is used to jump back

#### Common Limitations of StackGuard, Shadow Stack and StackShield

-   **Only protects the return address but no other important pointers**
-   Function pointers can be hijacked if the attacker cannot overwrite the return address due to canary

#### PointGuard

-   Compiler-based approach to protect function pointers from being overwritten
    -   Encrypt all points while stored in memory, decrypt them when loaded into CPU registers for use
-   Secret key is randomly generated for each program when launched
-   Pointer encryption happens when loading a pointer to memory by encrypting it with key (typically XOR)
-   Pointer decryption happens before a pointer is used by CPU
    -   **Ensuring pointer is in its original, unencrypted form only during actual use and minimizes window of vulnerability**

#### Pointer Authentication

-   Introduced in ARM to protect function pointers
    -   Appends a cryptographic signature known as Pointer Authentication Code (PAC) to pointers
    -   Allow CPU to verify integrity of pointers before they are used
-   Steps
    -   Pointer signing — when pointer is created or updated, PAC is generated using cryptographic hash of the pointer’s value and a secret key, then PAC is embedded into unused high-order bits of pointer
    -   Pointer verification — before pointer is used by CPU, system verifies its integrity by recalculating PAC and comparing it to the one stored in pointer, if match then pointer can be used
    -   Without knowing the correct key, attacker cannot generate the correct PAC

#### Non-Executable Memory

-   Attackers inject malicious code into memory and attempts to jump to it
-   We can configure writable memory region to be non-executable and thus preventing malicious code from being executed
-   System methods
    -   Linux uses ExecShield
    -   Winows uses Data Execution Prevention (DEP)
-   Hardware support
    -   AMD64
    -   Intel x86
    -   ARM
    -   Each page table entry has an attribute to control if page is executable
-   However, non-executable memory protection does not work when attacker does not inject malicious code, but just using existing code
    -   Return-to-lib attack
        -   Replace return address with address of an existing function in the standard C library or common OS function
    -   Return-oriented Programming
        -   Construct malicious code by chaining pieces of existing code (gadget) from different programs
        -   Gadget is a small set of assembly instructions that already exist in the system, ususally end with a return (ret), which pops the bottom of the stack as next instruction
    -   Use of executable heap for JIT compilation conflicts non-executable memory protection
        -   Just-in-time compilation compile heavily-used parts of the program while interpreting the rest
        -   Exploit runtime profiling to perform targeted optimizations thtn compilers targeting native code directly
        -   If non-executable memory protection is enabled, then cannot use JIT
            If JIT is used, then program is vulnerable to buffer overflow attacks

## Operating System Security 1

### Security Challenges in Modern OS

-   From single user to multi user
    -   DOS is truly single user
    -   MacOS, Linux, Windows are multi user
    -   Cloud computing allows multiple users all over the world to run on the same system and they do not know each other
        -   Not all user are trusted
-   From trusted apps to untrusted apps
    -   Simple real-time systems only run one specific app from trusted sources
    -   Time-sharing systems like modern PCs and smartphones run apps from third-party developers
        -   Not all apps are trusted
-   From standalone systems to networked systems
    -   Isolated computer systems only need to protect against physical threats
    -   Once connected to network, system faces external unknown threats
        -   Not all network components are trusted

### Security Protection Stages in OS

-   OS is reponsible for protecting apps and resources inside it
    -   OS controls what user/processes can do and cannot do

#### Authentication

-   Computer checks if a user is who they claim to be
    -   **Something you know — password, PIN, public/private keys**
    -   **Something you have — smart card, hardware tokens**
    -   **Something you are — biometrics, face recognition, voice recognition**

#### Something you Know

-   Password is the most common way to prove who you are
    -   Used in many applications
    -   Security of password-based authentication mechanism depends on strength of password
        -   Trade-off between security and convenience
    -   Weak password is a character combination that is easy for friends, bad actors or password-hacking software to guess
        -   Short passwords (singel word or numerical phrase)
        -   Recgonizable keystroke patterns (QWERTY)
        -   Personal information in password (birthday, name)
        -   Repeated letters or numbers
    -   Strong password is a long combination of unique characters that is difficult for other people to guess or technology to crack
        -   Lengthy combination with various character types such as numbers, letters and symboks
        -   Mnemonic where passwords are inspired by events only notable on one
        -   Non-dictionary words make it harder for software to crack as dictionary words are publicly known combinations stored in database where cybercriminals can access
    -   Requires periodic change and password must be different from the used ones to ensure strong authentication system

##### Something you Have

-   Different types of posessions for authentication
    -   Tokens
    -   Smart cards
-   Limitations of physical belongings
    -   Easy to misplace
    -   Often combined with user knowledge to form 2FA
    -   High cost
    -   Possible to be damaged
    -   Non-standard algorithms

##### Something you Are

-   Biometrics measure some physical characteristics
    -   Fingerprint, face recognition, retina scanners, voice
    -   Can be extremely fast and accurate
-   Limitations
    -   Private but no secret as biometrics may be emcoded surfaces like handles, glass
    -   Revocation is difficult as you cannot create a new one

#### Authorization

-   Access control implements a security policy that specifies who or what may have access to each specific resource in a computer system and the type of access that is permitted in each instance
-   Mediates between a user and system resource
-   Basic elements
    -   Subject
    -   Object
    -   Operations

#### Subject

-   Process or user requesting for access
-   Typically held accountable for the actions that is initiated
-   Types of subjects
    -   Owner — creator of a resource or system administrator for system resource
    -   Group — privilege can be assigned to a group of users where policy is applied to the entire group itself
    -   Other — least amount of access is granted to user who are able to access the system but no included in any categories
-   System administrator typically has highest privilege and can assign ownership to objects

#### Object

-   Resource that is security sensitive
-   Entity used to contain or receive information
-   Records, blocks, page, segments, files, directories, mailboxes, messages, programs

#### Operations

-   Actions taken using that resource
-   Read where user may view information and have the ability to copy or print
-   Write where user may modify data in the system resource
-   Execute where user may execute specified programs such as files or records
-   Delete where user may delete certain system resource such as files or records
-   Create where user may create new files or records
-   Search where user may list files in a directory or search

#### Access Control

##### Access Control Matrix

|            | **File 1**           | **File 2**           | **File 3**           | **File 4**           |
| ---------- | -------------------- | -------------------- | -------------------- | -------------------- |
| **User A** | Read, Write, Execute |                      | Read, Write, Execute |                      |
| **User B** | Read                 | Read, Write, Execute | Write                | Read                 |
| **User C** | Read, Write          | Read                 |                      | Read, Write, Execute |

-   New rows can be added for new subjects (typically done by system administrator)
-   New columns can be added for new objects (typically done by system administrator)
-   Permission $r$ can be granted for subject $s$ over object $o$ by entering $r$ to entry $M_{s,o}$ (typically done by the resource owner or system administrator)
-   Permission $r$ can be revoked for subject $s$ over object $o$ by removing $r$ from entry $M_{s,o}$ (typically done by the resource owner or system administrator)
-   Subject can be destoryed by deleting the row
-   Object can be destroyed by deleting column

##### Access Control List

-   Access control list is another way to represent control matrix given that it may be sparse
-   Decomposition
    -   By columns
    -   By rows
-   Decomposition by columns takes each object and ACL list users their permitted access rights
    -   Convenient when determining which subjects have what access to a particular resource
-   Decomposition by rows takes a C-list and specifiy authorized objects and operations for a particular user
    -   Convenient when determining the access rights available to a specific user
-   ACL is object oriented while C-list is subject oriented

#### Resource Management in Unix

-   Files, directories, memory devices and I/O devices are uniformly treated as resources
    -   Resources are objects of access control
    -   Each resource has a single user owner and group owner
-   Three permission with three subjects
    -   Read (r), write(w) and execute(x)
    -   Owner, group, other
    -   Examples
        -   rw-r—r—
            -   Read and write access for owner
            -   Read access for group
            -   Read access for others
            -   Represented as 110 100 100: 644 in octal
        -   rwx———
            -   Read, write and execute access for owner
            -   No access for group
            -   No access for other
            -   Represented as 111 000 000: 700 in octal
    -   Permissions can be adjusted by
        -   Change permission
            -   `chmod XXX` where XXX is the octal representation of desired permission
        -   Change ownership
            -   `chown user:group filename`

#### Controlled Invocation

-   Superuser privilege is required to execute certain OS functions
    -   Example
        -   Password changing
        -   User passwords are stored in file `/etc/shadow`
        -   FIle is owned by root superuser where a normal usr has no access to it
        -   When a normal user wants to change password with program passwd, program needs to give additional permisions to write to `/etc/shadow`
    -   SUID is a special permission flag for a program
        -   Allows a program to run with the permissions of its owner, rather than the user executing it
        -   When set on an executable file, the program runs as if launched by the file's owner, granting access to resources or actions the owner is authorized for, even if the user running it has lower privileges
        -   `/bin/login`, `/bin/at`, `/bin/su` are some SUID programs
-   Potential dangers
    -   As the user has the program owner’s privileges when running a SUID program, program should only do what the owner intended
    -   By tricking a SUID program owned by root to do unintended things, an attacker can act as the root
-   Security considerations
    -   All user input must be processed with extreme care
    -   Programs should have SUID status only if really necessary
    -   Integrity of SUID programs must be monitored

#### Logging, Monitoring and Auditing

-   Purposes
    -   Intrusion detection where unauthrozied access or system changes can be logged
    -   Forensics and investigation with historical data for incident response
    -   Accountability to track user actions and commands
    -   Performance monitoring to assist in debugging applications and diagnosing
-   Challenges
    -   High storage and processing requirements to precisely select and record critical data
    -   Attackers may erase of modify logs
    -   May compromise user privacy
-   Examples of monitored data
    -   System call traces describes the activities or behaviors of process running in system
    -   Log file is the information on user activity, including login record and keystroke command
    -   File integrity checksums periodically scan critical files for changes and compare cryptograhic checksums
    -   Register access monitor access to registry
    -   Kernel and driver-level monitoring this source provides insight into OS kernel-level anomalies
    -   Resource usage for CPU, memory and I/O utilization and activities can indicate malicious activities
    -   Network activities include established connections and received packets

#### Intrusion Detection

-   Intrusion Detection System (IDS) is a system used to detect unauthorized intrusions into computer systems
-   IDS can be implemented at different layers including network-based IDS, host-based IDS
-   Main focus here is on host-based IDS to monitor single host
-   Main components
    -   Sensors are responsible for collecting data
    -   Analyzers are repsonsible for determining if intrusion has occured and possible evidence with possible guidnace of actions to take
    -   User interface enables a user to view output from the system or control the behaviour of system
-   Detection methodologies
    -   Signature-based
        -   Flag any activity that matches structure of a known attack
        -   Maintain a blacklist of patterns that are not allowed
        -   Advantage
            -   Simple and easy to build
            -   Good at detecting known attacks
        -   Disadvantage
            -   Cannot catch new attacks without a known signature like zero-days
    -   Anomaly-based
        -   Develop a model what normal activities look like and alert on any activities that deviate from normal
        -   Whitelisting to keep a list of allowed patterns
        -   Advantage
            -   Can detect new attacks
        -   Disadvantage
            -   False positive rate can be high

### Privilege Management

-   Kernel mode has the highest privilege running the critical functions and services
    -   Technically, hypervisor has the highest privilege
-   User mode has the least privilege
-   Entities in higher rings cannot call functions and access objects in lower rings directly
    -   Context switch is required to achieve the calling
-   Status flag allows system to work in different modes

#### Context Switch

-   Different events can trigger transition from user to kernel levels
    -   System call is where user application explicity makes a request to kernel for privileged operations
    -   Trap is when user application gets an exceptional event (e.g. division by zero) or error (e.g. access data beyond memory region) and requests the kernel to handle
    -   System call and trap belong to software interrupts
    -   Hardware interrupt is when hardware issue a signal to the CPU to indicate an event needs immediate attention
-   Switch procedure
    -   CPU store processes state and swtich to kernel mode by setting status flag
    -   Kernel handles interrupt based on interrupt vector in interrupt table
    -   CPU switches back to user mode and restore states

#### System Call

-   Interface that allows user-level process to request functions or services from kernel level
-   Examples
    -   Process control
    -   File management
    -   Device management
-   Issuing a system call
    -   System call table contains pointers in the kernel region to different system call functions
    -   A user process passes the index of the system call and paramters with the API `syscall(SYS_CALL, arg1, arg2,…)`

#### Rootkit

-   Malware that obtains root privileges to compromise computer
    -   Root user does not go through any security checks and can perform any actions
    -   Hacker insert and execute arbitrary malicious code in system’s code path
    -   Hacker can hide its existence from being detected
-   Root privileges can be gained by a hacker through buffer overflow, format string and other vulnerabilities
    -   There can possibly be a flag on a stack that denotes privilege mode where hackers can overwrite using buffer overflow
-   Rootkit changes pointers of certian entries in system-call table
    -   Other processes calling these system calls will execute the attacker’s code
-   Example
    -   `syscall_open` is used to display running processes
    -   Rootkit redirects this sytem call to a malicious `new_syscall_open`
    -   If the name matches the malicious name (e.g., a file or process the rootkit wants to hide), the rootkit’s new_syscall_openreturns NULL, making it seem like the file doesn’t exist, so it’s hidden (e.g., from the ps command).
    -   Otherwise call normal `syscall`
-   Rootkit can also directly change system call functions
    -   In essence, the rootkit sneaks in, does its dirty work, and then hands control back to the legitimate system call, making it hard to detect while still achieving its malicious goals
    -   Target the syscall_open function: The syscall_open is a system call in the operating system that handles opening files. The rootkit aims to hijack this function.
    -   Replace the first 7 bytes: The rootkit modifies the first 7 bytes of the syscall_open function's code with a "jump" instruction. This jump redirects the program flow to a malicious function, malicious_open, instead of the normal syscall_open.
    -   Malicious function behavior:
        -   The malicious_open function runs some harmful code (e.g., logging sensitive file access, hiding specific files, or injecting malicious actions).
        -   After performing its malicious tasks, it restores the original 7 bytes of syscall_open to cover its tracks.
        -   Finally, it calls the original syscall_open function to ensure the system behaves as expected, so the user or system doesn't notice anything unusual

## Operating System Security 2

### Protection Strategies

-   An important security strategy in OS protection
    -   When some component in the system is compromised or malicious, need to prevent it from harming rest of the system
    -   Confinement restricts the impact of each component on others
    -   Follows the principle of least of privilege
    -   Can be implemented at different levels

#### OS Level Confinement — Virtual Machine

-   Virtualization is the fundemental technology for cloud computing
    -   Ability for different OS (VM) run on same machine
    -   Each virtual machine has an independent OS, logically isolated from others
-   For software layer, hypervisor is used for virtualizing and managing underlying resources and enforce isolation
    -   This makes hypervisor more privilege than OS kernel
    -   OS is usually privilege level 0 and hypervisor is in privilege level -1
    -   Hypervisor must ensure logical isolation
-   For hardware layer, hardware virtualization extensions (Intel VT-x, AMD-V) for accelerating virtualization and improving performance
-   Malware can be deployed onto VM to observe its behaviour
    -   Malware cannot cause damage outside of VM and thus not compromise the entire OS
    -   Malware behaviour can be observed from hypervisor
-   Limitations of virtualization
    -   Hypervisor introduces a large attack surface
        -   Hypervisor has big code base and inevitably brings more software bugs
        -   Hypervisor has higher privilege than OS kernel, if compromised, attacker can take control of entire system more easily
    -   Performance of VM could be affected by other VMs due to sharing of hardware resources
-   Challenges of virtualization
    -   Semantic gaps are present between high-level activties inside VMs and observed low-level behaviours
    -   **Not compatitable with Trusted Execution Environment (TEE)**
    -   Smart malware can detect that its running inside VM and not the actual environment intended for, thus behaving like normal application

#### Process Level Confinement — Container

-   Container is a standard unit of software that is lightweight, standalone, executable software package has everything eeded to run the application
    -   Code, system tools, libraries, configuration
-   Docker is commonyl used to manage containers
-   Advantages
    -   Portable, can run consistently across different environemnts, reducing compatability issues
    -   Efficiency, shraring OS reduces overhead with high resource utilization
    -   Isolation, applications operate in their own environment, minimizing conflicts and enhancing security
-   Process level, OS is not being virtualized

#### Reference Monitor

-   A concpetual framework that enforces access control policies over any protected target in a system
-   Meidates all access requests and deny any request that violates policy
-   Trusted Computer System Evaluation Criteria (TCSEC) emphasizes the need of a reference monitor in acheiving higher security
-   RM serve as foundation for various security models ensuring access control policies are consistently enforced across system
-   Requirements of RM
    -   Functional
        -   RM must intercept and evaluate every access request without exception
        -   RM is able to deny malicious requests
    -   Security
        -   RM must be tamper-proof and protected from unauthorized modification to maintain integrity
    -   Assurance
        -   Validation mechanism must be small enough to be thoroughly analyzed and tested for correctness
-   Access control policies can be secured with the use of RM to enforce the policies

#### OS-based RM

-   Core component within OS kernel
-   Enforces acess control policies by monitoring and mediating all system calls made by applications
-   Ensure all applications operate within their authorized permissions, prevent unauthroized access to system reousrces
-   Implementation
    -   Intercepts all system calls and check permissions to allow/disallow execution
    -   SELinux

#### Application-based RM

-   A security mechanism embedded within applications that enforce access control policies by providing fine-grained control over application behaviours
-   RM with interpreter
    -   Every operation will be checked against security policies before execution
-   Inline RM
    -   Inserting RM directly into application code

#### Hardware-based RM

-   Responsible for monitoring and regulating all software activities including OS kernel
    -   Any operation violating security policy will throw hardware exception
-   Conducts various checking
    -   Memoru access management
        -   If each memory access is within process memory rnage
        -   If each access follows the allowed permission
    -   Privilege mode mangement
        -   At any time, CPU can be in either user or kernel
        -   Privilege instructions can only be used in kernel mode
        -   Context switch is required for user mode to call privileged functions

#### Network-based RM

-   Firewall is used to monitor and regulate network traffic based on security policy
    -   Outbound defines what traffic is allowed to exit network
    -   Inbound defines what traffic is allowed to enter network
-   Possible actions
    -   Allow
    -   Deny
    -   Alert

### Hardware-assisted Protection

#### Basic Functionalities

-   Software is not always trusted
    -   Privileged software usually has very large code base which inevitably contains lots of vulnerabilities
    -   Once it is compromised, attacker can run anything to any apps
-   Hardware is more reliable
    -   More privileged
    -   After chip is fabricated, it is hard for attacker to modify it, integrity of chip is guaranteed
    -   Very hard for attacker to peek into the chip to steal secret, confidentiality guaranteed
    -   More reliable to introduce security-aware hardware to protect OS and applications

#### Encryption

-   Dedictaed hardware
    -   Trusted Platform Module (TPM)
    -   Hardware Security Module (HSM)
    -   Advanced Encryption Standard New Instructions (AES-NI)
-   Benefits
    -   Performance effiiciency that brings faster execution with optimized hardware
    -   Energy efficiency that lowers power consumption compared to software solutions
    -   Resistant to software-level attacks and malware
    -   Ease of use by having transparent encryption with minimal user interaction

#### Remote Attestation

-   Mechanism that allows a user to know if the app executes securely on a trusted platform
    -   Remote platform provides unforgeable evidence about the security of its software to a client
    -   Common strategy to prove software running on platform are intact and trustworthy
-   Components
    -   Integrity measurement architecture for providing reliable and trustworthy security report
    -   Remote attestation protocol ensuring the attestation report is transmitted to the client without being modified by attackers in OS, application or network

#### Trusted Platform Module

-   **A chip that is integrated into the platform and has a separated co-processor**
    -   Contains random number and key generators
    -   Crypto execution engine with different set of crypto keys
-   State cannot be compromised by malicious host system
-   Designed by Trusted Computing Group (TCG)
    -   First version TPM 1.1b released in 2003
    -   TPM 1.2 was equipped in PCs (2006) and servers (2008)
    -   Standardized by ISO and IEC in 2009
    -   Upgraded version TPM 2.0 released in 204
-   Application of TPM
    -   Intel Trusted Execution Technology (TXT)
    -   Microsoft Next-Generation Secure Computing Base (NGSCB)
    -   **Windows 11 requires TPM 2.0 as minimal system requirement**
    -   Linux kernel starts to support TPM 2.0 since version 3.20
    -   Google includes TPM in chromebooks
    -   VMware, Xen, KVM all support virtualized TPM

#### Building Chain of Trust using TPM

-   **Chain of trust establishes verified systems from bottom to top**
-   From a hierarchic view, a computer system is a layered system
    -   Lower layers have higher privileges and can protect upper layers
    -   Each layer is vulenrable to attacks from below if lower layer is not secured properly
-   **TPM serves as a root of trust that establishes secure boot process and continues until OS has fully booted and apps are running**
    -   Bottom layer validates the integrity of top layer
        -   Bottom layer protects top layer
    -   Safe to launch top layer omly when verification passes
-   Potential applications
    -   Digital right management
    -   Enforcement of software licenses
    -   Prevention of cheating in games
-   Integrity verification
    -   Only launches the layer the that passes the integrity verification
    -   Steps
        -   Loads the code from memory
        -   Compute hash value and verify signature
            -   Hash values checks that content or binary is unchanged
            -   Signature ensures that is from a trusted source
        -   Launch the code code if hash value matches and signature is valid
        -   Otherwise abort boot process

#### Data Encryption with TPM

-   Can perform full disk encryption
    -   Encrypts data with key in TPM
    -   Difficult for any attacker to steal the key that never leaves TPM
    -   TPM can also provide platform authentication before encryption
-   Windows BitLocker
    -   Disk data encrypted with encryption key FVEK
    -   FVEK is further encrypted with Storage Rook Key (SRK) in TPM - SRK is fixed in the TPM will never be known to others
    -   When decrypting data, BitLocker first asks TPM to verify platform integrity
    -   Then ask its TPM to decrypt FVEK with SRK
    -   Then BitLocker can use FVEK to decrypt data
    -   WIth this process, data can only be decrypted on the correct platform with the correct software launched

#### Remote Attestation with TPM

-   Integrity measurement architecture where TPM measures hash values of each loaded software as integrity report
-   Hash values are stored in Platform Configuration Registers (PCR) in TPM and cannot be compromised by OS or any other apps
-   Remote attestation protocol
    -   TPM generates an Attestation Identity Key (AIK) to sign hash values
    -   Hash values together with AIK will be sent to client
    -   Trusted third party, Privacy Certification Authority (PCA) is called to verify this AIK is indeed from correct platform
    -   Client uses this AIK to verify that received hash values are authentic
    -   By checking hash valuesm client knows it loaded software is correct

#### Trusted Execution Environment (TEE)

-   **Chain of trust can guarantee the integrity of secure booting but not runtime security**
    -   Even privilege software is botted with registry verification but may still be compromised at runtime
-   TEE introduces new hardware to protect the apps from untrusted OS or hypervisor where **only the OS or hypervisor can support execution of apps but not access data**
-   Intel Software Guard Extensions (SGX) is a security technology that safeguards application’s data and code
    -   Enclave is an isolated and protected region for the code and data of an application
    -   Data in the enclave are encrypted by processor when they are stored in memory
    -   Attempts from other apps or OS will be forbidden
-   Application execution in an enclave
    -   Applicaiton is diviced into trusted and untrusted parts
    -   Untrusted part creates an enclave and puts trusted part into it
    -   When trusted code needs execution, processor enter enclave
    -   In encalve, only trusted code and be executed and access the data
    -   After the code execution is done, processor exits enclave
    -   Untrusted part continues execution

#### Attestation with SGX

-   Integrity measurement architecture where enclave measurement of the code, data, stack, heap, security flags, location of each page
-   Attestation protocol where attestation key and cryptographic protocol are used
-   Remote attestation happens when remote client attests intergrity of code in enclave
-   Local attestation happens when multiple enclaves collaborate on the same task to exchange data at runtime, and can thus help to prove their trust

#### AMD Secure Encrypted Virtualization (SEV)

-   Hardware extension to protect VMs against untrusted hypervisor
    -   SEV has basic memory encryption (2016)
    -   SEV-ES has the ability to encrypt CPU registers (2018)
    -   SEV-SNP adds integrity protection (2020)
-   Mechanism
    -   Processor encrypts data of the guest VMs so hypervisor not allowed to access
    -   Uses an AMD secure processor to manage encryption keys
    -   Transparent encryption with minimal modifications to VM

#### AMD Secure Memory Encryption (SME)

-   Vritual memory encryption is realized by SME
    -   Perfomed via dedictaed hardware in memory controllers
    -   Uses AES engine to encrypt data and control with C-bit in page table entry
        -   If C-bit is enabled, then proceed to encrypt data before storing into memory
        -   If C-bit is disabled, then proceed to store in memory as no protection is required
    -   C-bit is located at physical address bit 47
    -   Setting C-bit to 1 indicates page is encrypted
        -   Give users the ability to encrypt full memory or selected pages

#### AMD TrustZone

-   First commercial TEE processor
-   Creates two environments that can run simultaeneously on same processor
    -   Each world has an independent OS
    -   Normal word runs the normal unprotected applications and has a rich OS, ahve restricted access to hardware resource in secure world
    -   Secure world runs the sensitive protected applications and a smaller secure OS that isolates them from untrusted world, ahve full access to hardware resource in normal world
-   Context switching
    -   Non-secure bit in the Secure Configuration Register is used to detemine which world processor is currently running
    -   Has a third privilege mode known as secure monitor in addition to user and kernel
    -   When processor wants to switch world, first issues a special instruction Secure Monitor Call (SMC) to enter secure monitor mode
    -   Then it performs cleaning works and enter other world

#### Application of TEE

-   Positive usage
    -   Cloud computing where trust is not needed for cloud provider
    -   Digital right management
    -   Crypto and blockchain
-   Negative usage
    -   Adversaries leverage TEE to hide malicious activities for stealthier attacks

## SingHealth Data Breach

### Overview

-   Between 23/8/17 and 20/7/18, cyberattack of unprecendeted scale and sophistication was carried on SingHealth patient database
-   Database was illegally accessed and personal particulars of 1.5 million patients, including names, NRIC numbers, addresses and dates of birth were exfiltrated over period of 27/6/18 to 4/7/18
-   Around 159000 of these 1.5 million patients also had their outpatient dispensed medication records exfiltrated
-   **PM Lee personal and outpatient medication data was specifically targeted and repeatedly access**
-   Crown jewels of SingHealth network are the patient Electronic Medical Records (EMR) contained in SingHealth “SCM” database
-   SCM is an EMR software solution that allows healthcare staff to access real-time patient data
-   Can be seen as comprising front-end workstations, Citrix servers and SCM database
-   Users would access SCM database via Citrix servers which operate as intermediary between front-end workstations and SCM database
    -   Citrix servers played a critical role in cyberattack
-   At the time of attack, SingHealth owns the SCM system
-   IHiS was reponsible for administering and operating the system including implementing cybersecurity measures
    -   Responsible for security incident response and reporting

### Stages

#### Stage 1

-   Attacker gained initial access to SingHealth’s IT network around 23/8/17, infecting front-end workstations most likely through phishing attacks
-   Attacker then lay dormant for 4 months, before commencing lateral movement for 6 months between December 2017 and June 2018, compomising many endpoints and severs including the Citrix servers located in SGH which were connected to the SCM database
-   Along the way, attacker also compromised a large number of user and administrator accounts

#### Stage 2

-   Starting from May 2018, attacker made use of compromised user workstations in SingHealth IT network and suspected VMs to remotely connect to SGH Citrix servers
-   Attacker initially unsuccessful to access SCM database from SGH citrix servers

#### Stage 3

-   **IHiS IT administrator first noticed unauthorised logins to Citrix servers and failed attempts at accessing SCM database on 11 June 2018**
-   **On 27 June 2018, attacker began querying SCM database, stealing and exfiltrating patient records and undetected by IHiS**

#### Stage 4

-   1 week later, on 4 July 2018, an IHiS administrator for the SCM system noticed suspicious queries being made on the SCM database
-   Working with others, ongoing suspicious queries were terminated and measures were put in place to prevent further queries to SCM database
-   Measures were successful and no further successful queries were made after 4 July 2018

#### Stage 5

-   Between 11 June and 9 July 2018, only IHiS line staff and middle management from various teams were aware
-   After 1 month on 9 July 2018, IHiS senior management were finally informed on this attack
-   3 days later on 10 July 2018, matter was escalated to Cyber Security Agency (CSA), SingHealth’s senior management, MOH and MOHH

#### Stage 6

-   Starting from 10 July 2018, IHiS and CSA carried out joint investigations and remediation
-   Several measures aimed at containing
    -   Existing threat
    -   Eliminating attacker’s footholds
    -   Preventing recurrence of attack
-   In view of further malicious activities on 19 July 2018, internet surfing separation was implemented for SingHealth on 20 July 2018
    -   No further suspicious activity after

#### Stage 7

-   Public annoucement was made on 20 July 2018
-   Patient outreach and communications commenced immediately thereafter
-   SMS were used for mass dissemination
-   COI committee has identified 5 key findings
-   COI committee has identified 5 key findings

### Key Findings

#### Inadequate Levels of Cybersecurity

-   IHiS staff did not have adequate levels of cybersecurity, training and resources
    -   Difficult for staff to appreciate security implications of their findings
    -   Cannot respond effectively

#### Lack of Ownership

-   Certain IHiS staff holding key roles in IT security incident response and reporting failed to take appropirate, effective or timely action
-   Resulted in missed opportunities to prevent stealing and exfiltrating of data

#### Vulnerabilities, Weaknesses and Misconfigurations

-   Number of vulnerabilities, weaknesses and misconfigurations in SingHeatlh network and SCM system that contributed to attacker’s success
-   Many could hvae been remedied before attack

#### Skilled and Sophisticated Actor

-   Bears the characteristics of an advanced persistent threat group that is skilled and sophistictaed
-   Attacker had a clear goal in mind, namely the personal data and outpatient medication data of PM primarily and other patients
-   Attacker employed advanced tools, techniques and procedures (TTP) as seen from the suite of advanced, customised and stealthy malware used
    -   Generally stealthy movements
    -   Ability to find and exploit various vulnerabilities in SingHealth IT network and SCM application
-   Attacker was persistent, having established multiple footholds and backdoors, carried out its attack over 10 months and made multiple attempts at accessing SCM database using various methods
-   Attacker was from a well-resourced group that has extensive command and control network with the capability to develop numerous customised tools, and wide range of technical expertise

#### Cyber Defences Will Never Be Impregnable

-   Difficult to prevent advanced persistent threat from breaching perimeter of network
-   Success of attacker in obtaining and exfiltrating data was not inevitable

### Cyber Kill Chain Framework

-   7 steps framework developed by Lockheed Martin
-   Identifies what adversaries must complete in order to achieve their objective
    -   Starting from early reconnaissance to final goal of data exfiltration
-   Facilitate understanding of the actions, tactics, techniques and procedures of attacker
-   7 steps
    -   Reconnaissance
    -   Weaponization
    -   Delivery
    -   Exploitation
    -   Installation
    -   Command and Control
    -   Actions on Objectives

#### First Evidence of Breach and Establishing Control

-   Forensic investigations uncovered signs of callbacks to overseas command and control server from 23 Auguest 2017
    -   Callbacks are communications between malware and server to either fetch updates and instructions or send back stolen information
-   CSA discovered many malicious artifacts in workstation A
    -   A log file which was remnant of a malware set
        -   Log file was a remnant file from a known malware which has password dumping capability
        -   Created on workstation A on 29 Auguest 2017 that contains password credentials in plaintext that appeared to belogn to user of workstation A
        -   Malware was likely to have been used attacker to obtain passwords for privilege escalation and lateral movement
    -   Publicly available hacking tool
        -   Enables attacker to maintain persistent presence once an email account has been breached even if password is subsequently changed
        -   Interact remotely with mail exchange servers
        -   Perform simple brute force attacks on user’s email account password
        -   Serve as hidden backdoor for attacker to regain entry into system in the event initial implants are removed
        -   **Installed on workstation A on 1 Dec 2017 by exploiting a vulnerability in the version of Outlook that was installed on workstation A**
        -   **Although patch was available at that time, it was not installed then**
        -   Hacking tool was thus successfully installed and was used to download malicious files onto workstation A
            -   **Some of these files were masqueraded as .jpg image files but in fact contained malicious PowerShell scripts, one of which is thought to be a modified PowerShell script taken from open source post-exploitation tool**
    -   Customised remote access trojan referred to as “RAT 1”
        -   RAT 1 provided attacker with capability to access and control workstation A enabling attacker to perform functions such as executing shell scripts remotely and uploading and downloading files
-   Introduction of hacking tool and RAT 1 in Dec 2017 allowed the attacker to gain capability to execute shell scripts remotely as well as upload and download files to workstation A
    -   Attacker was able to go through delivery, exploitation, installation, command and control phases by 1 Dec 2017

#### Privilege Escalation and Lateral Movement

-   Happened from December 2017 to June 2018
-   After attacker established an initial foothold in workstation A, it moved laterally in network between December 2017 and June 2018
    -   Compromising a number of endpoints and servers
    -   Including Citrix servers located in SGH which were connected to SCM database
-   Evidence of attacker’s lateral movement was found in proliferation of malware across endpoints and servers
    -   **Malware samples found and analysed by CSA were either tools that were stealthy by deisgn or unique varients not seen in the wild and not detected by standard anti-malware solutions**
    -   Malware included RAT 1 and another “RAT 2”
-   Evidence of PowerShell commands used by attacker to distribute malware to infect other machines and other of malicious files being copied between machines over mapped network drives
-   **CSA also assessed that attacker is likely to have compomised Windows authentication system and obtain administrator and user credentials**
    -   Allows attacker to gain full control over all Windows based servers and hosted applications and all employee workstations, underlying data within domain
-   Established control over workstation B on 17 April 2018
    -   Attacker gain access to workstation B (SGH) and planted RAT 2
    -   Workstation B has access to SCM application
    -   Used to log in remotely to SGH Citrix servers 1 and 2

#### Queries to SCM Database

-   Happened from 26 June 2018 to 4 July 2018
-   AA account was used to query database from Citrix server 2
-   3 types of queries ran
    -   Reconnaissance on schema of SCM database
    -   Direct queries relating to particular individuals
    -   Bulk queries on patients
-   Information from SQL queries
    -   PM Lee personal and outpatient medication data
    -   Demographic records of 1.5 million patients including names, NRIC, address, gender, race and dates of birth
    -   Outpatient dispensed medication records of about 159k of 1.5 million patients
-   Copying and exfiltration of data from SCM database was stopped on 4 July 2018 after staff from IHiS discovered unusal queries and took steps to prevent further querying

#### Attempts to Re-enter SingHealth Network

-   Happened on 18 and 19 July 2018
-   After detection of malware on communications from server, CSA recommended internet surfing separation should be implemented to prevent attacker from exercising command and control over remaining footholds
-   **Internet surfing separation implemented on 20 July 2018**
-   No further signs deteceted thereafter

### Contributing Factors Leading to Attack

#### Network Connections between SGH Citrix Servers and SCM Database

-   Connection were allowed
-   **Open connection is not necessary**
    -   Need to reduce attack surface area
-   Basic security review of network architecture and connectivity between SGH Citrix servers and SCM database could have shown that open network connection created a security vulnerability
    -   But no review was carried out
-   **Lesson: get rid of unncessary connection**

#### Lack of Monitoring at SCM Database for Unusual Queries

-   From 26 June to 4 July 2018, attacker ran queries on SCM database including bulk queries undetected
-   Lack of monitoring of SCM database
    -   No existing controls to detect bulk queries
    -   No control place at the time of attack to detect of block any queries to SCM database made using illegitimate applications
-   Database Activity Monitoring (DAM) solutiosn were available on the market that can address some or all gaps
    -   **DAM not implemented by IHiS at the time of attack**

#### SGH Citrix Servers Not Adequately Secure Against Unauthorised Access

-   Privilege Access Management was not the exclusive means for accessing for accessing SGH Citrix servers
-   Login to servers by other means without 2FA were possible
-   **IHiS Citrix administrators were aware of this but made use of this for convenience**
-   **Lack of firewalls to prevent unauthorised remote access using RDP to SGH Citrix servers**
-   SGH Citrix servers were not treated as mission critical unlike SCM databse
    -   Not monitored for real-time analysis and alerts of vulneratbilites and issues arising
    -   Vulnerability scanning not carried out for SGH Citrix servers but only for mission critical systems

#### Internet Connectivity in SingHealth IT Network Increased Attack Surface

-   Connection to internet while serving operational needs created an evenue of entry and exit for attacker
-   Allowed attacker to make use of internet-connected workstation (workstation A) to gain entry to the network before making its way to SCM database to steal data
-   Security risks from internet-connectivity were raised by CSA to MOH as early as August 2015
-   By June 2017, healthcare sector determined that
    -   Internet access would be removed for staff that did not require internet for work
    -   For those required, access would be through a secure internet access platform which was to take the form of a “remote browser”

#### Versions of Outlook used by IHiS Not Patched

-   Publicly available hacking tool can compromise Outlook
-   Attacker was able to install the tool on workstation A by exploting the vulnerability in version of Outlook that was installed on workstation
-   Patch was effective in preventing vulnerability from being exploited and available in late 2017
-   **Clear need to improve software upgrade policies**

#### Extensive Command and Control Infrastructure

-   CSA forensic analysis revelaed a number of network Indicators of Compromise (IOC) which appeared to be overseas command and control servers
-   Used for
    -   Infection where server is used as means of dropping malware into system it is trying to infect
    -   Data exfiltration where inidications of technical data being sent
    -   Beacon where infected machines may have connected to servers to establish a heartbeat which refers to slow and rhythmic communcation mean to just sustain connections

### Actions of COI

-   Made 16 recommendations, 7 of which are priority to be implemented immediately

#### Enhanced Security Structure and Readiness

-   Cybersecurity must be viewed as risk management issue and not technical issue
    -   Decisions must be deliberated at appropriate management level to balance trade-offs between security, operational requirements and cost
-   IHiS must adopt a defence in depth approach
-   Gaps between policy and practice must be addressed

#### Cyber stack Must be Reviewed

-   Identify gaps in cyber stack by mapping layers of IT stack against existing security technologies
-   Gaps in response technologies must be filled by acuqring endpoint and network forensics capabiltiies
-   Effectiveness of current endpoint security measures must be reviewed to fill gaps exploited by attacker
-   Network security must be enhanced to disrupt command and control and actions on objective phases of Cyber Kill Chain
-   Application security for email must be heightened

#### Staff Awareness on Cybersecurity must be Improved

-   Level of cyber hygiene among users must continue to be improved
-   Security awareness programme should be implemented to reduce organisational risk
-   IT staff must be equipped with sufficient knowledge to recognise signs of security incident

#### Enhanced Security Checks must be Performed on Command and Control Systems

-   Vulnerability assessments must be conducted regularly
-   Safety reviews, evaluation and certifcation of vendor products must be carried out where feasible
-   Penetration testing must be conducted regularly
-   Red teaming should be carried out periodically
-   Threat hunting must be considered

#### Privileged Administrator Accounts must be Subject to Tigheter Control and Greater Monitoring

-   An inventory of adminstrative accounts should be created to faciliate rationalisation of such accounts
-   All administrators must use 2FA when performing adminstrative tasks
-   Use of passphrases instead of passwords should be considered to reduce risk of acocunts being compromised
-   Password policies must be implemented and enforced across both local and domain accounts
-   Server local administrator accounts must be centrally managed across IT network
-   Service accounts with high privileges must be managed and controlled

#### Incident Response Process must be Improved for More Effective Response

-   Ensure response plans are effective and must be tested regularly
-   Pre-defined modes of communications must be used during incident response
-   Correct balance msut be struck between containment, remediation and eradication
-   Information and data necessary to investigate an incident must be readily available
-   Cyber defence centre should be established

#### Partnerships betwen Industry and Government

-   Threat intelligence sharing should be enhanced
-   Partnerships with ISPs should be strengthened
-   Defence beynd borders where cross-border and cross-sector partnerships should be strengthened
-   Using a network to defend a network by applying behavioural analytics for collective defence

#### Additional Recommendations

-   IT security risk assessments and audit processes must be treated seriosuly and carried out regularly
-   Enhanced safeguards must be put in place to protect EMR
-   Domain controllers must be secured against attack
-   Robust patch management process must be implemented to address security vulnerabilities
-   Software update policy with focus on security must be implemented to increase cyber resilience
-   Internet access strategy that minimises exposure to external threats should be implemented
-   Incident response plans must be more clearly state when and how security indicent is to be reported
-   Competence of computer security incident response personnel must be significantly improved
-   A post-breach independent forensic review of network, endpoins and SCM system should be considered
