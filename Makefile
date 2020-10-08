#Frances Astorian

JAVAC=javac

.SUFFIXES: .java .class


.java.class:
	$(JAVAC) $*.java

CLASSES = Crypto.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	rm -f *.class

