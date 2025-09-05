# SC3010 Computer Security

## Topics

-   Introduction
-   Basics of Cyber Security
-   Software Security 1
-   Software Security 2
-   Software Security 3
-   Operating System Security 1

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
    -   Can take more than one argument where first argument is the format string and the rest consists of values to ve substituted
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
    -   `%d` format specifiers tell printf to expect three integer values, which are provided as x, y, and z
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
    -   Use `%n` to store the number of characters printed so far (5) into the memory address provided as an argument\
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
    -   Compiler suppirt to match `printf` arguments with format strings

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

-   Scirpting languag is used to
    -   Construct commands from predefined code fragments and user input at runtime
    -   Script is then passed to another software component where it is executed
    -   Domain-specific language is used for a particular environemnt
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
    -   Instruct browser to only use resources loaded form specific places
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
    -   Identify issues during development and reduces cost of fixing vulenrability
    -   Relies on predefined rules or policies to identify patterns of insecure coding practice
-   Limations
    -   May produce false positives requring manual review
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
    -   Require expert analysis to assess whether system crashes are explitable
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

## Operating System Security 1

### Security Challenges in Modern OS

-   From single user to multi user
    -   DOS is truly single user
    -   MacOS, Linux, Windows are multi user
    -   Cloud computing allows multiple users all over the world to run on the same system and they do not know each other
        -   Not all user are trusted
-   From trusted apps to untrusted apps
    -   Simple real-time systems only run one specific app from trusted sources
    -   Modern PCs and smartphones run apps from third-party developers
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

#### Subject

-   Process or user requesting for access
-   Typically held accountable for the actions that is initiated
-   Types of subjects
    -   Owner — creator of a resource or system administrator for system resource
    -   Group — privilege can be assigned to a group of users where policy is applied to the entire group itself
    -   Other — least amount of access is granted to user who are able to access the system but no included in any categories

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
        -   User passwords are stored in file /etc/shadow
        -   FIle is owned by root superuser where a normal usr has no access to it
        -   When a normal user wants to change password with program passwd, program needs to give additional permisions to write to /etc/shadow
    -   SUID is a special permission flag for a program
        -   Allows a program to run with the permissions of its owner, rather than the user executing it
        -   When set on an executable file, the program runs as if launched by the file's owner, granting access to resources or actions the owner is authorized for, even if the user running it has lower privileges
-   Potential dangers
    -   As the user has the program owner’s privileges when running a SUID program , program should only do what the owner intended
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
            -   Cannot catch new attacks without a known signature
    -   Anomaly-based
        -   Develop a model what normal activities look like and alert on any activities that deviate from normal
        -   Whitelisting to keep a list of allowed patterns
        -   Advantage
            -   Can detect new attacks
        -   Disadvantage
            -   False positive rate can be high

### Privilege Management

-   Kernel mode has the highest privilege running the critical functions and services
-   User mode has the least privilege
-   Entities in higher rings cannot call functions and access objects in lower rings directly
    -   Context switch is required to achieve the calling
-   Status flag allows system to work in different modes

#### Context Switch

-   Different events can trigger transition from user to kernel levels
    -   System call is where user application explicity makes a request to kernel for privileged operations
    -   Trap is when user application gets an exceptional event or error and requests the kernel to handle
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
