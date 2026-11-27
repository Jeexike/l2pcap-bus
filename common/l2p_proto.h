#pragma once
#include <cstdint>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

constexpr uint16_t L2P_ETHERTYPE = 0x88B5;     // Заголовок для экспериментального протокола
constexpr uint32_t L2P_MAGIC     = 0x4C32504B; // L2PK (для отсеивания случайных кадров с тем же EtherType)
constexpr uint8_t  L2P_VERSION   = 1;          // Версия протокола L2P
constexpr size_t   L2P_MAX_DATA = 1360;        // Максимальный размер куска данных в одном кадре

enum class MsgType : uint8_t { // Типы сообщений
    DATA     = 2, // Producer отправляет очередной кусок файла
    START    = 1, // Producer открывает сессию и сообщает метаданные
    FIN      = 3, // Producer сообщает, что все пакеты отправлены
    ACK_META = 4  // Consumer->Producer (подтверждение приема кадра)
};

enum AckStatus : uint8_t { // Код состояния в ответе от Consumer
    STATUS_OK         = 0, // Все прошло штатно (или FIN)
    STATUS_INCOMPLETE = 1, // Получено FIN, но приняты не все пакеты
    STATUS_BAD_CRC    = 2  // Контрольная сумма входящего кадра не сошлась
};

#pragma pack(push, 1) // Выравнивание по 1 байту (критично для сетевого протокола)

struct EthHeader {      // Заголовок Ethernet II
    uint8_t  dst[6];    // MAC-адрес получателя
    uint8_t  src[6];    // MAC-адрес отправителя
    uint16_t ethertype; // EtherType в сетевом порядке
};

struct FrameHeader {      // Заголовок протокола L2P (24 байта)
    uint32_t magic;       // Сигнатура L2PK в сетевом порядке байт
    uint8_t  version;     // Версия протокола
    uint8_t  type;        // Значение MsgType
    uint16_t reserved;    // Зарезервированные байты
    uint32_t session_id;  // Уникальный ID сессии передачи файла
    uint32_t seq;         // Порядковый номер пакета
    uint32_t total;       // Общее количество пакетов в сессии
    uint16_t payload_len; // Длина полезной нагрузки после этого заголовка
    uint32_t crc32;       // CRC32 по FrameHeader + payload
};

struct ConsumerMeta {        // Метаданные приема
    uint32_t acked_seq;      // Подтвержденный порядковый номер пакета
    uint32_t received_pkts;  // Количество полученный уникальных пакетов
    uint32_t expected_pkts;  // Количество ожидаемых пакетов по START
    uint64_t received_bytes; // КОличество байт полезной нагрузки
    uint8_t  status;         // Код из AckStatus
    uint8_t  crc_ok;         // 1 - CRC32 принятого кадра верен, 0 - ошибка
    uint16_t pad;            // Выравнивание структуры до 24 байт
};

#pragma pack(pop) // Возвращени к стандартному выравниванию

// Преобразование 64-битных чисел между порядком хоста и сетевым порядком
uint64_t htonll_u64(uint64_t val);
uint64_t ntonll_u64(uint64_t val);

// Расчет контрольной суммы CRC32
uint32_t calc_crc32(const uint8_t* data, size_t len);

// Сборка Ethernet-кадра
std::vector<uint8_t> make_frame(
    const uint8_t dst_mac[6],
    const uint8_t src_mac[6],
    MsgType type,
    uint32_t session_id,
    uint32_t seq,
    uint32_t total,
    const uint8_t* payload,
    uint16_t payload_len
);

// Разбор сырого Ethernet-кадра (true, если валидный)
bool parse_fframe(
    const uint8_t* raw,
    size_t caplen,
    EthHeader& out_eth,
    FrameHeader& out_hdr,
    const uint8_t*& out_payload,
    bool& out_crc_ok
);