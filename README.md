# SC3010 Computer Security

## Topics

-   Introduction
-   Basics of Cyber Security
-   Software Security 1

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
