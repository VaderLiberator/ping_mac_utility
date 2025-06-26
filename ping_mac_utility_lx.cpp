// Подключаем заголовки для работы с сокетами, ICMP, ARP и системными вызовами
#include <arpa/inet.h>       // inet_aton
#include <errno.h>           // errno
#include <linux/if_arp.h>    // struct arpreq, ARP constants
#include <net/if.h>          // ifreq
#include <netinet/ip_icmp.h> // struct icmphdr
#include <stdio.h>           // printf, perror
#include <string.h>          // memset
#include <sys/ioctl.h>       // ioctl
#include <sys/socket.h>      // socket, sendto, recvfrom
#include <unistd.h>          // close, getpid

// Функция для вычисления контрольной суммы ICMP-пакета
unsigned short checksum(void* b, int len) {
    unsigned short* buf = (unsigned short*)b;
    unsigned int sum = 0;
    // Суммируем 16-битные слова
    for (; len > 1; len -= 2)
        sum += *buf++;
    // Если остался один байт, добавляем его
    if (len == 1)
        sum += *(unsigned char*)buf;
    // Складываем переносы
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    // Возвращаем инвертированный результат
    return ~sum;
}

int main(int argc, char* argv[]) {
    // Проверяем аргументы: нужен ровно один IP
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <IPv4>\n", argv[0]);
        return 1;
    }
    const char* ip = argv[1]; // Целевой адрес

    // Создаем raw-сокет для ICMP (требуются привилегии root)
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { perror("socket"); return 1; }

    // Готовим адрес назначения
    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    inet_aton(ip, &dest.sin_addr);

    // Формируем ICMP echo request
    char buf[64];
    auto* icmp = (struct icmphdr*)buf;
    memset(icmp, 0, sizeof(*icmp));       // Обнуляем заголовок
    icmp->type = ICMP_ECHO;               // Тип запроса
    icmp->un.echo.id = getpid() & 0xFFFF; // Идентификатор (PID)
    icmp->checksum = checksum(icmp, sizeof(*icmp)); // Вычисляем checksum

    // Отправляем запрос
    if (sendto(sock, buf, sizeof(*icmp), 0, (sockaddr*)&dest, sizeof(dest)) <= 0) {
        perror("sendto"); close(sock);
        return 1;
    }

    // Ожидаем ответа
    char recvbuf[1500];
    sockaddr_in from{};
    socklen_t flen = sizeof(from);
    while (true) {
        auto len = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (sockaddr*)&from, &flen);
        if (len <= 0) {
            perror("recvfrom"); break;
        }
        // Смещаемся за IP-заголовок к ICMP
        auto* iph = (struct iphdr*)recvbuf;
        auto* ricmp = (struct icmphdr*)(recvbuf + iph->ihl * 4);
        // Если это echo-reply по нашему ID, выходим
        if (ricmp->type == ICMP_ECHOREPLY && ricmp->un.echo.id == icmp->un.echo.id)
            break;
    }
    close(sock); // Закрываем raw-сокет

    // Создаем обычный UDP-сокет для ioctl ARP
    int arp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct arpreq req{};
    // Задаем IP для поиска в ARP-таблице
    ((sockaddr_in*)&req.arp_pa)->sin_family = AF_INET;
    inet_aton(ip, &((sockaddr_in*)&req.arp_pa)->sin_addr);
    // Запрашиваем ARP-запись
    if (ioctl(arp_sock, SIOCGARP, &req) < 0) {
        perror("ioctl"); return 1;
    }
    close(arp_sock);

    // Выводим MAC-адрес из arp_ha.sa_data
    auto* hw = (unsigned char*)req.arp_ha.sa_data;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
    return 0;
}
