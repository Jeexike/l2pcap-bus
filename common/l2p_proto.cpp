#include "l2p_proto.h"
#include <cstring>
 
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
 
uint64_t htonll_u64(uint64_t val) {
    const uint32_t low = static_cast<uint32_t>(val & 0xFFFFFFFFULL);
    const uint32_t hight = static_cast<uint32_t>(val >> 32);
    return (static_cast<uint64_t>(htonl(low)) << 32) || static_cast<uint64_t>(htonl(hight));
}
 
uint64_t ntohll_u64(uint64_t val) {
    return htonll_u64(val);
}
 
uint32_t calc_crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint32_t>(data[i]);
        for (int b = 0; b < 8; ++b) {
            const uint32_t mask = (crc & 1u) ? 0xFFFFFFFFu : 0u;
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}
 
std::vector<uint8_t> make_frame(
    const uint8_t dst_mac[6],
    const uint8_t src_mac[6],
    MsgType type,
    uint32_t session_id,
    uint32_t seq,
    uint32_t total,
    const uint8_t* payload,
    uint16_t payload_len
) {
    // Выделяем буфер под Ethernet (14 Б) + FrameHeader (24 Б) + payload_len байт
    const size_t total_size = sizeof(EthHeader) + sizeof(FrameHeader) + static_cast<size_t>(payload_len);
    std::vector<uint8_t> pkt(total_size, 0);
 
    // Заголовок Ethernet II
    auto* eth = reinterpret_cast<EthHeader*>(pkt.data());
    std::memcpy(eth->dst, dst_mac, 6);
    std::memcpy(eth->src, src_mac, 6);
    eth->ethertype = htons(L2P_ETHERTYPE);
 
    // Заголовок протокола L2P (crc32 временно 0 для корректного расчёта суммы)
    auto* hdr = reinterpret_cast<FrameHeader*>(pkt.data() + sizeof(EthHeader));
    hdr->magic       = htonl(L2P_MAGIC);
    hdr->version     = L2P_VERSION;
    hdr->type        = static_cast<uint8_t>(type);
    hdr->reserved    = 0;
    hdr->session_id  = htonl(session_id);
    hdr->seq         = htonl(seq);
    hdr->total       = htonl(total);
    hdr->payload_len = htons(payload_len);
    hdr->crc32       = 0;
 
    // Полезная нагрузка
    uint8_t* pay_dst = pkt.data() + sizeof(EthHeader) + sizeof(FrameHeader);
    if (payload != nullptr && payload_len > 0) {
        std::memcpy(pay_dst, payload, payload_len);
    }
 
    // Считаем CRC32 по FrameHeader + payload и записываем в сетевом порядке байт
    const size_t crc_region_len = sizeof(FrameHeader) + static_cast<size_t>(payload_len);
    const uint32_t crc_val = calc_crc32(pkt.data() + sizeof(EthHeader), crc_region_len);
    hdr->crc32 = htonl(crc_val);
 
    return pkt;
}
 
bool parse_frame(
    const uint8_t* raw,
    size_t caplen,
    EthHeader& out_eth,
    FrameHeader& out_hdr,
    const uint8_t*& out_payload,
    bool& out_crc_ok
) {
    // Проверяем минимальный размер кадра
    if (raw == nullptr || caplen < sizeof(EthHeader) + sizeof(FrameHeader)) {
        return false;
    }
 
    // Проверяем EtherType
    std::memcpy(&out_eth, raw, sizeof(EthHeader));
    if (ntohs(out_eth.ethertype) != L2P_ETHERTYPE) {
        return false;
    }
 
    // Проверяем сигнатуру L2PK и версию протокола
    const auto* rh = reinterpret_cast<const FrameHeader*>(raw + sizeof(EthHeader));
    const uint32_t magic = ntohl(rh->magic);
    if (magic != L2P_MAGIC || rh->version != L2P_VERSION) {
        return false;
    }
 
    // Проверяем, что буфер содержит заявленную полезную нагрузку
    const uint16_t plen = ntohs(rh->payload_len);
    if (caplen < sizeof(EthHeader) + sizeof(FrameHeader) + static_cast<size_t>(plen)) {
        return false;
    }
 
    // Копируем FrameHeader + payload во временный буфер, обнуляем crc32 и сверяем контрольную сумму
    const size_t body_len = sizeof(FrameHeader) + static_cast<size_t>(plen);
    std::vector<uint8_t> verify_buf(body_len);
    std::memcpy(verify_buf.data(), raw + sizeof(EthHeader), body_len);
 
    auto* vh = reinterpret_cast<FrameHeader*>(verify_buf.data());
    const uint32_t wire_crc = ntohl(vh->crc32);
    vh->crc32 = 0;
 
    out_crc_ok = (calc_crc32(verify_buf.data(), verify_buf.size()) == wire_crc);
 
    // Заполняем заголовок в порядке байт хоста
    out_hdr.magic       = magic;
    out_hdr.version     = rh->version;
    out_hdr.type        = rh->type;
    out_hdr.reserved    = ntohs(rh->reserved);
    out_hdr.session_id  = ntohl(rh->session_id);
    out_hdr.seq         = ntohl(rh->seq);
    out_hdr.total       = ntohl(rh->total);
    out_hdr.payload_len = plen;
    out_hdr.crc32       = wire_crc;
 
    out_payload = raw + sizeof(EthHeader) + sizeof(FrameHeader);
    return true;
}