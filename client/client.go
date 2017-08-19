package main

import (
	"fmt"
)

func Sqrt(x float64) float64 {
	delta := 0.01
	for x_1 := 0; x_1 - x > delta || x_1 - x < delta ; {
		x_1 = x
		x = x - ((math.pow(x,2) - x) / (2*x))
	}
}

func main() {
	fmt.Println(Sqrt(2))
}
