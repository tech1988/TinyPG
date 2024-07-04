#ifndef TINYPGTEMPLATES_H
#define TINYPGTEMPLATES_H

#include <initializer_list>
#include <tuple>
#include <algorithm>

namespace TinyPG
{

#define _BOOLOID 16
#define _INT8OID 20
#define _INT2OID 21
#define _INT4OID 23
#define _FLOAT4OID 700
#define _FLOAT8OID 701
#define _DATEOID 1082
#define _TIMEOID 1083
#define _TIMETZOID 1266
#define _TIMESTAMPOID 1114
#define _TIMESTAMPTZOID 1184
#define _OIDOID 2278
#define _BYTEAOID 17
#define _REGPROCOID 24
#define _XIDOID 28
#define _CIDOID 29
#define _CHAROID 18
#define _VARCHAROID 1043
#define _TEXTOID 25
#define _UUIDOID 2950

#define PG_NegotiateProtocolVersion 0x76
#define PG_ErrorResponse 0x45
#define PG_NoticeResponse 0x4e
#define PG_AuthenticationRequest 0x52
#define PG_AuthenticationSucces 0x00
#define PG_PasswordMessage 0x70
#define PG_ParameterStatus 0x53
#define PG_BackendKeyData 0x4b
#define PG_ReadyForQuery 0x5a
#define PG_MD5password 0x05
#define PG_SASL 0x0a
#define PG_SASL_Continue 0x0b
#define PG_SASL_Complete 0x0c
#define PG_Idle 0x49
#define PG_Transaction 0x54
#define PG_Exit 0x45
#define PG_ErrorOrNoticeType 0x56
#define PG_ErrorOrNoticeCode 0x43
#define PG_ErrorOrNoticeMessage 0x4D
#define PG_Parse 0x50
#define PG_Bind 0x42
#define PG_ParseComplite 0x31
#define PG_BindCompletion 0x32
#define PG_RowDescription 0x54
#define PG_DataRow 0x44
#define PG_NoData 0x6e
#define PG_CommandCompletion 0x43
#define PG_EmptyQueryResponse 0x49
#define PG_Describe 0x44
#define PG_Statement 0x53
#define PG_ParameterDescription 0x74

static constexpr std::initializer_list<std::size_t> BOOL = {_BOOLOID};
static constexpr std::initializer_list<std::size_t> INT2 = {_INT2OID};
static constexpr std::initializer_list<std::size_t> INT4 = {_INT4OID, _OIDOID, _REGPROCOID, _XIDOID, _CIDOID};
static constexpr std::initializer_list<std::size_t> INT8 = {_INT8OID};
static constexpr std::initializer_list<std::size_t> FLOAT4 = {_FLOAT4OID};
static constexpr std::initializer_list<std::size_t> FLOAT8 = {_FLOAT8OID};
static constexpr std::initializer_list<std::size_t> DATE = {_DATEOID};
static constexpr std::initializer_list<std::size_t> TIME = {_TIMEOID};
static constexpr std::initializer_list<std::size_t> TIMETZ = {_TIMETZOID};
static constexpr std::initializer_list<std::size_t> TIMESTAMP = {_TIMESTAMPOID, _TIMESTAMPTZOID};
static constexpr std::initializer_list<std::size_t> BYTEA = {_BYTEAOID};
static constexpr std::initializer_list<std::size_t> TEXT = {_CHAROID, _VARCHAROID, _TEXTOID};
static constexpr std::initializer_list<std::size_t> UUID = {_UUIDOID};

static constexpr std::initializer_list<std::initializer_list<std::size_t>> TYPES = {
    BOOL,INT2,INT4,INT8,FLOAT4,FLOAT8,DATE,TIME,TIMETZ,TIMESTAMP,BYTEA,TEXT,UUID
};

static constexpr std::size_t TypeMax()
{
    std::size_t max = 0;
    for(const auto & v : TYPES) max = std::max(max, *std::max_element(v.begin(), v.end()));
    return max;
}

template<typename T, std::size_t N = TypeMax()>struct VariantValues
{
    T values[N+1];

    template<typename F = T(*)(T)>constexpr VariantValues(std::initializer_list<std::tuple<std::initializer_list<std::size_t>, T>> list, F convert = nullptr):values()
    {
        for(const auto & v : list)
        {
            for(auto idx : std::get<0>(v))
            {
                if(convert == nullptr) values[idx] = std::get<1>(v);
                else values[idx] = convert(std::get<1>(v));
            }
        };
    }

    constexpr std::size_t size() const { return N; }
};

template<std::size_t N>struct GotoPointers
{
    void * pointers[N+1];

    constexpr GotoPointers(void * _default, std::initializer_list<std::tuple<std::size_t, void *>> list):pointers()
    {
        for(int i = 0; i < N+1; i++) pointers[i] = _default;

        for(const auto & v : list) pointers[std::get<0>(v)] = std::get<1>(v);
    }

    constexpr GotoPointers(void * _default, std::initializer_list<std::tuple<std::initializer_list<std::size_t>, void*>> list):pointers()
    {
        for(int i = 0; i < N+1; i++) pointers[i] = _default;

        for(const auto & v : list)
        {
            for(auto idx : std::get<0>(v))
            {
                pointers[idx] = std::get<1>(v);
            }
        };
    }

    constexpr std::size_t size() const { return N; }
};

#include <QMetaType>

constexpr auto toVariants = VariantValues<QMetaType::Type>(
{
    {BOOL,QMetaType::Bool},
    {INT2,QMetaType::Short},
    {INT4,QMetaType::Int},
    {INT8,QMetaType::LongLong},
    {FLOAT4,QMetaType::Float},
    {FLOAT8,QMetaType::Double},
    {DATE,QMetaType::QDate},
    {TIME,QMetaType::QTime},
    {TIMETZ,QMetaType::QDateTime},
    {TIMESTAMP,QMetaType::QDateTime},
    {BYTEA,QMetaType::QByteArray},
    {TEXT,QMetaType::QString},
    {UUID,QMetaType::QUuid}
});

}

#endif // TINYPGTEMPLATES_H
