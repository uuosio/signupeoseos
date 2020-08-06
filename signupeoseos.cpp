//
// Created by Hongbo Tang on 2018/7/5.
//

#include "signupeoseos.hpp"
// #include <eosio/types.h>
// #include <eosio/crypto.h>

static eosio::symbol CORE_SYMBOL = eosio::symbol("UUOS", 4);

void signupeoseos::transfer(account_name from, account_name to, asset quantity, string memo) {
    if (from == _self || to != _self) {
        return;
    }
    check(quantity.symbol == CORE_SYMBOL, "signupeoseos only accepts CORE for signup eos account");
    check(quantity.is_valid(), "Invalid token transfer");
    check(quantity.amount > 0, "Quantity must be positive");

    memo.erase(memo.begin(), find_if(memo.begin(), memo.end(), [](int ch) {
        return !isspace(ch);
    }));
    memo.erase(find_if(memo.rbegin(), memo.rend(), [](int ch) {
        return !isspace(ch);
    }).base(), memo.end());

    auto separator_pos = memo.find(' ');
    if (separator_pos == string::npos) {
        separator_pos = memo.find('-');
    }
    check(separator_pos != string::npos, "Account name and other command must be separated with space or minuses");

    string account_name_str = memo.substr(0, separator_pos);
    check(account_name_str.length() >= 8, "Length of account name should be >= 8");
    account_name new_account_name(account_name_str);

    string public_key_str = memo.substr(separator_pos + 1);

    check(public_key_str.length() == 54, "Length of publik key should be 53");

    string pubkey_prefix("UUOS");
    auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), public_key_str.begin());
    check(result.first == pubkey_prefix.end(), "Public key should be prefix with EOS");
    auto base58substr = public_key_str.substr(pubkey_prefix.length());

    vector<unsigned char> vch;
    check(decode_base58(base58substr, vch), "Decode pubkey failed");

    check(vch.size() == 37, "Invalid public key");

    array<unsigned char,33> pubkey_data;
    copy_n(vch.begin(), 33, pubkey_data.begin());

    checksum160 check_pubkey = ripemd160(reinterpret_cast<char *>(pubkey_data.data()), 33);
    auto _check_pubkey = check_pubkey.extract_as_byte_array();
    check(memcmp(_check_pubkey.data(), &vch.end()[-4], 4) == 0, "invalid public key");

    asset stake_net(1000, CORE_SYMBOL);
    asset stake_cpu(4000, CORE_SYMBOL);
    asset buy_ram = quantity - stake_net - stake_cpu;
    check(buy_ram.amount > 0, "Not enough balance to buy ram");

    signup_public_key pubkey = {
        .type = 0,
        .data = pubkey_data,
    };
    key_weight pubkey_weight = {
        .key = pubkey,
        .weight = 1,
    };
    authority owner = authority{
        .threshold = 1,
        .keys = {pubkey_weight},
        .accounts = {},
        .waits = {}
    };
    authority active = authority{
        .threshold = 1,
        .keys = {pubkey_weight},
        .accounts = {},
        .waits = {}
    };
    newaccount new_account = newaccount{
        .creator = _self,
        .name = new_account_name,
        .owner = owner,
        .active = active
    };

    action(
            permission_level{ _self, "active"_n },
            "eosio"_n,
            "newaccount"_n,
            new_account
    ).send();

    action(
            permission_level{ _self, "active"_n},
            "eosio"_n,
            "buyram"_n,
            make_tuple(_self, new_account_name, buy_ram)
    ).send();

    action(
            permission_level{ _self, "active"_n},
            "eosio"_n,
            "delegatebw"_n,
            make_tuple(_self, new_account_name, stake_net, stake_cpu, true)
    ).send();
}

#define EOSIO_DISPATCH_EX( TYPE, MEMBERS ) \
extern "C" { \
    void apply( uint64_t receiver, uint64_t code, uint64_t action ) { \
        auto self = receiver; \
        if( action == N(onerror)) { \
            /* onerror is only valid if it is for the "eosio" code account and authorized by "eosio"'s "active permission */ \
            check(code == N(eosio), "onerror action's are only valid from the \"eosio\" system account"); \
        } \
        if((code == N(eosio.token) && action == N(transfer)) ) { \
            switch( action ) { \
                EOSIO_DISPATCH_HELPER( TYPE, MEMBERS ) \
            } \
            /* does not allow destructor of thiscontract to run: eosio_exit(0); */ \
        } \
   } \
}

EOSIO_DISPATCH_EX( signupeoseos, (transfer) )
