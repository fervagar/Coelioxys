#!/usr/bin/env python
# -*- coding: latin-1 -*-

# Fernando Vanyo <fervagar@tuta.io>

from __future__ import print_function;
import traceback;
from argparse import ArgumentParser;
from sys import argv, stdout, stderr;
from os.path import isfile;
import struct;

def inform(*msg):
  print("[+]", *msg, file=stdout);

def error(*error):
  print("[-]", *error, file=stderr);

def checkELF(data):
  magic = struct.unpack('<L', data[0x00:0x04])[0];
  if magic != 0x464c457f:
    return False;
  arch = struct.unpack('<H', data[0x12:0x14])[0];
  if arch != 0x03:
    return False;
  return True;

def askUser():
  reply = str(raw_input('Are you sure you want to continue...? [y/N]: ')).lower().strip();
  if len(reply) > 0 and reply[0] == 'y':
    return True;
  else:
    return False;

def readContents(filename):
  with open(filename, 'rb') as f:
    data = f.read();
  return data;

def writeContents(filename, data):
  with open(filename, 'wb') as f:
    f.write(data);

def getLoadSegments(pht, esize, nsegm):
  hasNoteSegment = False;
  segmentsList = [];
  sgmOffset = 0;
  PT_LOAD = 1;
  PT_NOTE = 4;

  for i in range(0, nsegm):
    idx = (i * esize);
    stype = struct.unpack('<L', pht[idx : idx+4])[0];
    if stype == PT_LOAD:
      ## Look if the segment has RWE attributes
      flags = struct.unpack('<L', pht[idx+4*6 : idx+4*7])[0]
      if flags == 0x7: 
        segmentsList.append(pht[idx : idx+4*8]);
        sgmOffset = idx;
    elif stype == PT_NOTE:
      hasNoteSegment = True;

  return segmentsList, sgmOffset, hasNoteSegment;

def fixup(segment, elf, dataPtr, offset):
  coelioxys_size = 0x29c;

  restored = [];
  for i in range(0, 0x18):
    restored.append(dataPtr[i]);

  ## Retrieve the original Entry Point ##
  ep_offset = 0x182;
 
  ##orig_ep = hex(struct.unpack('<L', segment[ep_offset:(ep_offset+4)])[0])[2:];
  try:
    j = 0;
    for i in range(0x18, 0x1c):
      restored.append(segment[ep_offset+j]);
      j += 1;

    for i in range(0x1c, offset):
      restored.append(dataPtr[i]);

  except:
    return False;

  ## Clear the segment header
  for i in range(0, 4*8):
     restored.append('\x00');

  for i in range((offset + 4*8), len(dataPtr)-coelioxys_size):
    restored.append(dataPtr[i]);

  ## Delete the padding
  item = restored[-1];
  while item == '\x00':
    item = restored.pop();
  restored.append(item);
  restored.append('\00');

  data = ''.join(chr(struct.unpack('<B', x)[0]) for x in restored);
  writeContents(elf, data);

  return True;

def _treat(elf, usermode):
  coelioxys_EP = 0x70000000;
  ret = False;

  if not isfile(elf):
    return -1;

  contents = readContents(elf);
  if len(contents) < 0x34 or not checkELF(contents):
    return -2;

  entryPoint = struct.unpack('<L', contents[0x18:0x1c])[0];
  
  ## Search the second LOAD Segment ##
  phoff = struct.unpack('<L', contents[0x1c:0x20])[0];
  phentsize = struct.unpack('<H', contents[0x2a:0x2c])[0];
  phnum = struct.unpack('<H', contents[0x2c:0x2e])[0];
  phtsize = phnum * phentsize;
  ## Get the Program Header Table ##
  pht = contents[phoff:(phoff + phtsize)];	## Program Header Table

  try:
    segmentsList, sgmOffset, hasNoteSegment = getLoadSegments(pht, phentsize, phnum);
    length = len(segmentsList);
    if length == 0:
      return 1;
      
    elif length > 1:
      return -3;
    else:
      segment = segmentsList[0];
      segm_offset = struct.unpack('<L', segment[4*1 : 4*2])[0];
      segm_size = struct.unpack('<L', segment[4*4 : 4*5])[0];
      segment = contents[segm_offset : (segm_offset+segm_size)];
      if hasNoteSegment and (entryPoint != coelioxys_EP):
        return 2;
      elif hasNoteSegment:
        if usermode:
          inform("This ELF has a NOTE segment...");
          ## Ask the user to continue...
          if askUser():
            ret = fixup(segment, elf, contents, (phoff+sgmOffset));
        else:
          ret = fixup(segment, elf, contents, (phoff+sgmOffset));
      else:
        if usermode and (entryPoint != coelioxys_EP):
          inform("Seems like this ELF is not infected by Coelioxys...");
          if askUser():
            ret = fixup(segment, elf, contents, (phoff+sgmOffset));
        else:
          ret = fixup(segment, elf, contents, (phoff+sgmOffset));
    if ret:
      return 0;
    else:
      return 2;

  except:
    None;
    ##traceback.print_exc();

## For external imports ##
def ApplyCoelioxysVaccine(filename):
  _treat(filename, False);

def main():
  parser = ArgumentParser(description='This is the Vaccine for the Coelioxys virus.\nIt can be used directly or as a imported library.\nIn the second case, use the function ApplyCoelioxysVaccine(filename). Fernando Vanyo <fervagar@tuta.io>');
  parser.add_argument('<infected file>', type=str, help='ELF binary file infected by Coelioxys')
  args = vars(parser.parse_args());

  filename = args['<infected file>'];
  ret = _treat(filename, True);

  if ret == -3:
    error("This tool cannot fix this ELF... Sorry.");
  elif ret == -2:
    error("Bad file: %s" % filename);
  elif ret == -1:
    error("'%s' is not a file!" % filename);
  elif ret == 0:
    inform("The recovery of the file '%s' has been successful" % filename);
  elif ret == 1:
    inform("The ELF is free of Coelioxys");
  else:
    inform("The provided binary is not infected");

if __name__ == '__main__':
  main();


