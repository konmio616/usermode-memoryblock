#include "security.h"

int main()
{
	security::initialize();
	while (1)
	{
		security::memoryBlock();
	}
}
