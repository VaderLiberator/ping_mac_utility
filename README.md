# ping_mac_utility
Этот код содержит две реализации утилиты на C++: для Linux и для Windows. Обе версии: 1. Отправляют ICMP echo-запрос (Ping) на указанный IPv4-адрес. 2. Получают ответ и определяют MAC-адрес отправителя. 3. Выводят MAC-адрес в stdout в формате `xx:xx:xx:xx:xx:xx`.

# Компиляция и запуск
(Linux, root требуется):

Компилируем исходник:

g++ -o ping_mac_utility ping_mac_utility.cpp

Запускаем с правами root для raw-сокетов и ioctl:

sudo ./ping_mac_utility 192.168.1.1

(Windows, Visual Studio Developer Command Prompt):
Убедитесь, что Windows SDK установлен и пути к библиотекам настроены.

cl /EHsc ping_mac_utility_win.cpp /link ws2_32.lib iphlpapi.lib  // Линкуем WinSock и IP Helper API (включает ICMP)

Запуск утилиты
ping_mac_utility_win.exe <ip address>
