#include "Driver.h"
#include <iostream>

int main()
{
	//	MoaRpm rpm("star wars battlefront", MoaRpm::MOA_MODE::KERNEL);
	MoaRpm rpm("star wars battlefront", MoaRpm::MOA_MODE::NTDLL);
	//MoaRpm rpm("star wars battlefront", MoaRpm::MOA_MODE::STANDARD);
	auto pGameContext = rpm.read<DWORD_PTR>(0x142AE8080);
	auto pPlayerManager = rpm.read<DWORD_PTR>(pGameContext + 0x68);
	auto pLocalPlayer = rpm.read<DWORD_PTR>(pPlayerManager + 0x550);
	auto pLocalSoldier = rpm.read<DWORD_PTR>(pLocalPlayer + 0x2cb8);
	rpm.write<byte>(pLocalSoldier + 0x02AC, 241);
	auto playerName = rpm.readString(rpm.read<DWORD_PTR>(pLocalPlayer + 0x18));
	std::cout << "player name\t" << playerName << std::endl;
	getchar();
	return 0;
}
