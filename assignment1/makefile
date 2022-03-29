add-nbo : func.o main.o
	g++ -o add-nbo func.o main.o

func.o : func.cpp
	g++ -c -o func.o func.cpp

main.o : main.cpp
	g++ -c -o main.o main.cpp

clean :
	rm *.o add-nbo
