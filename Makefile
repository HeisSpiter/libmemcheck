CXX	= g++
CXXFLAGS= -O0 -fPIC -W -Wall -Wextra

LIB	= libmemcheck.so
OBJ	= mutex.o garbagecollector.o

all: $(LIB)

$(LIB): mutex.o garbagecollector.o
	$(CXX) $(CXXFLAGS) -shared -o $(LIB) $(OBJ) -ldl
#	$(CXX) $(CXXFLAGS) -shared -o $(LIB) $(OBJ) -ldl -lunwind

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $< -o $@ -ldl
#	$(CXX) -c $(CXXFLAGS) -D_DBG_ $(CPPFLAGS) $< -o $@ -ldl
#	$(CXX) -c $(CXXFLAGS) -D_UNWIND_ $(CPPFLAGS) $< -o $@ -ldl -lunwind

clean:
	rm -rf *.o

distclean: clean
	rm -rf *.so
