CXX	= g++
CXXFLAGS= -O0 -fPIC -W -Wall -Wextra

LIB	= libmemcheck.so
OBJ	= mutex.o garbagecollector.o

all: $(LIB)

$(LIB): mutex.o garbagecollector.o
	$(CXX) $(CXXFLAGS) -shared -o $(LIB) $(OBJ) -ldl

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $< -o $@ -ldl
#	$(CXX) -c $(CXXFLAGS) -D_DBG_ $(CPPFLAGS) $< -o $@ -ldl

clean:
	rm -rf *.o

distclean: clean
	rm -rf *.so
