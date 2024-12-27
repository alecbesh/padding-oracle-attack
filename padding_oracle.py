
import json
import sys
import time
from typing import Union, Dict, List

import requests

s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)


    negSize = len(message)*(-1)
    padGuess = 0x01
    b = bytearray(message)
    Cp = -1
    index = -17
    finalPlain = [-1] * (len(message) - 16)
    outputIdx = -1
    numBlocks = 0
    maxBlocks = (len(message) / 16) - 1


    while (index >= -32) and (numBlocks < maxBlocks):
        g = 0x00
        newList = []
        while g <= 0xFF:
            temp = bytearray(b)
            temp[index] = g
            newList.append(temp)
            g += 0x01

        response = []
        response = oracle(oracle_url, newList)
        numValid = 0
        for i in range(0,256):
            if response[i]["status"] == "invalid_mac":
                Cp = i
                numValid += 1

        if (numValid == 0):
            for i in range(0,256):
                if response[i]["status"] == "valid":
                    Cp = i
                    numValid += 1
              
        
        if (numValid > 1):
            g = 0x00
            newList = []
            
            if index > negSize: b[index - 1] = (b[index - 1] + 1) % 255

            while g <= 0xFF:
                temp = bytearray(b)
                temp[:] = b
                temp[index] = g
                newList.append(temp)
                g += 0x01

            
            response = []
            response = oracle(oracle_url, newList)
            numValid = 0
            for i in range(0,256):
                if response[i]["status"] == "invalid_mac":
                    Cp = i
                    numValid += 1

            if (numValid == 0):
                for i in range(0,256):
                    if response[i]["status"] == "valid":
                        Cp = i
                        numValid += 1


        D = Cp ^ padGuess
        P = D ^ message[index]

        finalPlain[outputIdx] = P
        outputIdx -= 1
        
        i = -17
        j = -1
        padGuess += 0x01
        while i >= index:
            Cpp = message[i] ^ finalPlain[j - (16*numBlocks)] ^ padGuess
            b[i] = Cpp
            i -= 1
            j -= 1

        index -= 1



        # If moving onto next block, chop off last block
        if index == -33:
            message = message[:-16]
            b = bytearray(message)
            index = -17
            numBlocks += 1
            padGuess = 0x01





    # Remove Padding and Mac and then decrypt
    remove = finalPlain[-1]
    finalPlain = finalPlain[:-remove]
    
    remove = 32
    finalPlain = finalPlain[:-remove]

    decrypted = bytes(finalPlain)
    
    print(decrypted.decode())
    
    
    


if __name__ == '__main__':
    main()
