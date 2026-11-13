# fo_keycrack -- build GPU (nvcc) o CPU (gcc)
# make gpu   -> binario CUDA 'fo_keycrack'      (richiede nvcc + GPU Nvidia)
# make cpu   -> binario CPU   'fo_keycrack_cpu' (fallback, richiede solo gcc)

gpu:
	nvcc -O3 -o fo_keycrack fo_keycrack.cu -lz

cpu:
	gcc -O3 -x c -DNO_CUDA -o fo_keycrack_cpu fo_keycrack.cu -lz

clean:
	rm -f fo_keycrack fo_keycrack_cpu
