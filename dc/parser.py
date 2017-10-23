from configparser import RawConfigParser

class IntelConfigParser(RawConfigParser):
    '''Configuration parser that saves configuration file format'''
    def __init__(self):
        RawConfigParser.__init__(self)
        self.optionxform = str

    def get_config(self, fil = None):
        '''Read in old configuration file, return new configuration string'''
        sections = self.sections()
        sections.sort()
        names, lines, outputlines = [], [], []
        items = {}
        currentsection = None
        if fil is not None:
            # If file is readable, get the existing config with which to
            # merge, otherwise just return a brand new config
            startpos = fil.tell()
            fil.seek(0)
            try:
                if 'r' in fil.mode:
                    lines = fil.read().split('\n')
            except: pass
        numlines = len(lines)
        i = 0
        while i < numlines:
            line = lines[i]
            strippedline = line.strip()
            if not strippedline or strippedline[0] == '#':
                # Leave blank lines and comments intact
                pass
            elif strippedline[0] == '[' and strippedline[-1] == ']':
                if currentsection is not None:
                    # New section started, but we still have items for the old
                    # section, so write them out first
                    for name, value in items.items():
                        outputlines.append('%s = %s' % (name, value))
                    sections.remove(currentsection)
                currentsection = strippedline[1:-1]
                if currentsection in sections:
                    items = dict([(unicode(item[0]).strip(), unicode(item[1]).strip()) for item in self.items(currentsection)])
                else:
                    # Section was removed from the configuration, so delete
                    # all related lines
                    currentsection = None
                    i += 1
                    try: strippedline = lines[i].strip()
                    except IndexError: break
                    while not (strippedline and strippedline[0] == '[' and strippedline[-1] == ']'):
                        i += 1
                        try: strippedline = lines[i].strip()
                        except IndexError: break
                    continue
            elif strippedline.count('=') or strippedline.count(':'):
                name, value = '', ''
                poseq, poscol = -1, -1
                # Name-value pairs can be separated by either : or =.
                # Find the separator closest to the left, and split there
                try: poseq = strippedline.index('=')
                except ValueError: name, value = strippedline.split(':',1)
                else:
                    try: poscol = strippedline.index(':')
                    except ValueError: name, value = strippedline.split('=',1)
                    else:
                        if poseq < poscol:
                            name, value = strippedline.split('=',1)
                        else:
                            name, value = strippedline.split(':',1)
                name = name.strip()
                value = value.strip()
                if name in items:
                    if value != items[name]:
                        line = '%s = %s' % (name, items[name])
                    del items[name]
                else:
                    # Item was removed from the configuration, so ignore the line
                    i += 1
                    continue
            outputlines.append(line)
            i += 1
        if currentsection is not None:
            for name, value in items.items():
                # File ended, but we still have items left for the last section
                outputlines.append('%s = %s' % (name, value))
            sections.remove(currentsection)
        for section in sections:
            # File ended, but there were sections added to the configuration
            # so we need to add them and their values
            outputlines.append('')
            outputlines.append('[%s]' % section)
            outputlines.append('')
            for name, value in self.items(section):
                outputlines.append('%s = %s' % (name, value))
        if fil is not None:
            # Return the file to its starting position
            fil.seek(startpos)
        return '\n'.join(outputlines)

