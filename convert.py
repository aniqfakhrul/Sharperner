#/usr/bin/env python3
import sys

class CustomMorse:
    def __init__(self, _input):
        self._input = _input
        self.morses = {'a':'.-','A':'^.-','b':'-...','B':'^-...','c':'-.-.','C':'^-.-.','d':'-..','D':'^-..','e':'.','E':'^.','f':'..-.','F':'^..-.','g':'--.','G':'^--.','h':'....','H':'^....','i':'..','I':'^..','j':'.---','J':'^.---','k':'-.-','K':'^-.-','l':'.-..','L':'^.-..','m':'--','M':'^--','n':'-.','N':'^-.','o':'---','O':'^---','p':'.--.','P':'^.--.','q':'--.-','Q':'^--.-','r':'.-.','R':'^.-.','s':'...','S':'^...','t':'-','T':'^-','u':'..-','U':'^..-','v':'...-','V':'^...-','w':'.--','W':'^.--','x':'-..-','X':'^-..-','y':'-.--','Y':'^-.--','z':'--..','Z':'^--..','0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.','/':'/','=':'...^-','+':'^.^','!':'^..^','.':'^^^.__-'}

    def encode(self):
        for i in self._input:
            for alp,mor in self.morses.items():
                if i == alp:
                    print(mor, end=" ")
                    break

    def decode(self):
        code = self._input.split(" ")
        for c in code:
            for alp,mor in self.morses.items():
                if c == mor:
                    print(alp, end="")
                    break

def main():
    try:
        _input = sys.argv[1]
    except IndexError as e:
        print("No string provided")
        return
    morse = CustomMorse(_input)
    morse.encode()
    morse.decode()

if __name__ == "__main__":
    main()
