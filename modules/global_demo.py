count = 0
word_file = open('passwd.txt')
wordlist = word_file.readlines()
for i in wordlist:
    print "Line number[%s]" % str(count+1)
    print i

word_file.close()
