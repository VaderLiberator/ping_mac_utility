// Подключаем WinSock, IP Helper API и ICMP API
#include <winsock2.h>  // WSADATA, WSAStartup, SOCKET
#include <iphlpapi.h>  // SendARP
#include <icmpapi.h>   // IcmpCreateFile, IcmpSendEcho
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")    // Линкуем WinSock
#pragma comment(lib, "iphlpapi.lib")  // Линкуем IP Helper API (включает IcmpSendEcho)


int main(int argc, char* argv[]) {
    // Проверяем, передан ли IP-адрес
    if (argc != 2) {
        printf("Usage: %s <IPv4>\n", argv[0]);
        return 1;
    }
    const char* ip = argv[1];

    // Инициализируем WinSock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    // Отправка ICMP Echo (Ping)
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) { perror("IcmpCreateFile"); return 1; }

    unsigned long destIP = inet_addr(ip);
    char sendData[32] = "Data"; // Полезная нагрузка
    // Буфер для ответа, включающий заголовок и данные
    char recvBuf[sizeof(ICMP_ECHO_REPLY) + sizeof(sendData)];

    // Отправляем и ждем до 1000 мс
    DWORD ret = IcmpSendEcho(hIcmp, destIP,
                             sendData, sizeof(sendData),
                             nullptr, recvBuf, sizeof(recvBuf), 1000);
    if (ret == 0) { printf("Ping failed\n"); return 1; }

    // Обрабатываем ответ
    auto* reply = (ICMP_ECHO_REPLY*)recvBuf;
    printf("Reply from %s, RTT=%ld ms\n", ip, reply->RoundTripTime);

    // Запрос ARP для определения MAC-адреса
    ULONG MACAddr[2];
    ULONG PhysAddrLen = 6;            // Ожидаем длину 6 байт
    memset(&MACAddr, 0xff, sizeof(MACAddr)); // Инициализируем

    ret = SendARP(destIP, 0, &MACAddr, &PhysAddrLen);
    if (ret != NO_ERROR) { printf("SendARP failed: %ld\n", ret); return 1; }

    // Выводим MAC-адрес
    BYTE* bPhysAddr = (BYTE*)&MACAddr;
    if (PhysAddrLen) {
        printf("MAC: ");
        for (int i = 0; i < (int)PhysAddrLen; i++)
            printf(i ? ":%02x" : "%02x", bPhysAddr[i]);
        printf("\n");
    }

    // Освобождаем ресурсы
    IcmpCloseHandle(hIcmp);
    WSACleanup();
    return 0;
}