'''
Copyright (C) 2020 Josh Schiavone - All Rights Reserved
You may use, distribute and modify this code under the
terms of the MIT license, which unfortunately won't be
written for another century.

You should have received a copy of the MIT license with
this file. If not, visit : https://opensource.org/licenses/MIT
'''

import random
from termcolor import cprint, colored

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray
BOLD = '\033[1m'
END = '\033[0m'


def LoadEspionageBanner():
  '''
  Outputs the espionage ascii art on startup.
  @param None
  @return None
  '''
  print(W + BOLD + "\n    _______________    " + BOLD + R + "* *    ")
  print(G + BOLD +"==c(___(o(______(_()     * *   ")
  print(G + BOLD + "        \=\              * *     ")
  print(G + BOLD + "         )=\            * *      ")
  print(G + BOLD + "         //|\\          " + BOLD + R + "* *     ")
  print(G + BOLD + "        //|| \\                ")
  print(G + BOLD + "       // ||  \\               ")
  print(G + BOLD + "      //  ||   \\              ")
  print(W + BOLD + "     //         \\ {}          ".format(random.choice(entry_phrases)) + END)
  print(B + BOLD + "_____________________________________" + END)
  print(W+ BOLD + "             ["+G+"Espionage"+W+"]                  " + END)
  print(W + "-==[ " + BOLD + "A Network Traffic Interceptor" + END)
  print(W + "-==[ " + BOLD + "Developed By: Josh Schiavone    " + END)
  print(B + BOLD + "_____________________________________\n" + END)

entry_phrases = [
    'Sniff All The Things.',
    'God Bless Telescopes.',
    'Wiretap The World.',
    'She Loves Espionage.',
    'Be The Man-in-the-middle.',
]


def EspionageBreaker():
  '''
  Function to be called to breakup cluttered data.
  @param None
  @return None
  '''
  breaker = colored('''
  ====================================================================================
  ''', 'grey', attrs=['bold'])
  print(breaker)
