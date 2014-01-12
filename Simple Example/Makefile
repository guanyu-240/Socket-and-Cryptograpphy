JAVAC=javac

GCJ=$(JAVAC)

MAINCLASS=fcrypt
PROGRAM=fcrypt

SOURCES= \
src/fcrypt.java \
src/org/crypt/Encrypt.java \
src/org/crypt/Decrypt.java 

Compile and tar:
	rm -rf bin/ 
	mkdir bin/
	echo "Main-Class: $(MAINCLASS)" > Manifest
	$(JAVAC) -g -d bin $(SOURCES)
	jar cfm $(PROGRAM).jar Manifest -C bin/ .
