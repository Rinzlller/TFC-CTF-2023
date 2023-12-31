# TFC-CTF-2023
Writeups from TFC CTF 2023 (exactly for PWN tasks)

**PWN category [solved by me] :**
- diary
- shello-world
- random
- easyrop
- rusty
- pwngate
- notes

## Diary | Warmup
**Vuln**: BoF without canaries.
**Solution**: You know addresses of ELF, but you know nothing about Libc -- version, base. So, there is suppoused to use jmp rsp asm command in helper function:

    void helper()
    {
      __asm { jmp     rsp }
    }

This gadgets allows you to execute a shellcode into a stack, but this technique requires  RWX stack's permissions, as in our case. Just put a shellcode into the stack and rewrite ret address to "jmp rsp" via BoF. That's exactly what I did in diary.py.

## Shello-world | Warmup
**Vuln**: Format-string within win function.
**Solution**: There is format-string vuln which means write-what-where primitive, so out target is GOT table. We need to rewrite address of function (like **putchar**) that will be execute once in the end of the main function. Just rewrite this address to win function and get a shell. Press F to win mb.

## Random | Easy
**Vuln**: seed for srand() is process' start time.
**Solution**: There is tipical vuln for random function:

    void main(int argc, const char **argv, const char **envp) {
	    ...
	    t = time(0LL);
	    srand(t);
	    ...

If we know process' start time (so we do), we can predict all of set values which will be returned by rand function. It allows us to call win() and get a shell.

In this case it's need to use C rand function. Because I write my sploits on python, I just write one another programm my_rand.c to call correct rand function, that is executed by my sploit.

## Easyrop | Easy
**Vuln**: write/read-what-where primitives (not exactly).
**Solution**: In this task we are supposed to write ROP chain within restriction from author - we can't edit each third int (4 bytes) on stack. It was so hard and terrific, but I solved this ****. The main trouble for me was RDI and RSI registers, which should be zero at the moment of start execve("/bin/sh"). We can find gadgets like
- pop rdi; ... ret
- pop rsi; ... ret

and so on, also we know one_gadget address (because libc is provided). We can disclose libc base address by arbitrary-read (not exactly) primitive on stack.

The main problem for me was need to zeroed RSI and RDI. I decided to make it via pop gadgets with hope that zeroes will be on stack. Not everywhere. But... A few ours of game with stack and ta-da-da :) There aren't words that could describe my feelings.
  
## Rusty | Medium
**Vuln**: Bof

**Solution**: There is a classic BoF with password check, but in rust programm. That's all.

## Pwngate | Medium
**Vuln**: BoF with last element of list

**Solution**: To solve this task you need to rewrite the last element of the timeline list, then play with encryption of long ints in memory and finally BoF with a function pointer. There is nothing complicated.
You should be carefully with bounders of for-cycles and size in fgets:

    void __fastcall divergence_meter() {
	    ...
	    if ( input[i] == 0x6F && id )
	        id = youdidwhat(id);
	      else
	        timeline[id++] = input[i];
	      if ( (int)id > 8 )			# /!\ can be 8 when timeline[0..7]
	        break;
For generating correct long int "ld" that will pass both checks:

    __int64 ld;
    __isoc99_scanf("%ld", &ld);		# 0x????
    
    if ( !ld ) {					# 0xadea7ac400000000
	    exit(0)
	}
	...
	if ( (unsigned int)ld ) {		# 		  0x00000000
	    exit(0)
	}
    
I compile scanf-printf programm on C and execute this with gdb.
 
## Notes | Medium
**Vuln**: heap overflow

**Solution**: There is heap overflow just because this typo:

    note_t* add() {
	    ...
	    fgets(note->content, sizeof(CONTENT_MAX), stdin);
	    ...
	}
	
	void edit(note_t* note) {
	    printf("content> \n");
	    fgets(note->content, CONTENT_MAX, stdin);
	}

So we can create an 8-byte note and then write 256 bytes into it to overwrite the next note's context address, it gives us write-what-where primitive. Hello, GOT table and win function ;)