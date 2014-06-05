CXX	= g++
CXXFLAGS= -fPIC -W -Wall -Wextra

LIB	= libmemcheck.so
OBJ	= mutex.o garbagecollector.o

all: $(LIB)

$(LIB): mutex.o garbagecollector.o
	$(CXX) $(CXXFLAGS) -shared -o $(LIB) $(OBJ) -ldl

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $< -o $@

clean:
	rm -rf *.o

distclean: clean
	rm -rf *.so
