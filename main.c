#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

// Estrutura de Transação (Voto)
typedef struct {
    char chave[65];        // Chave única (ex: um hash SHA-256)
    char candidato[20];    // Nome ou ID do candidato
} Transacao;

// Estrutura de Bloco
typedef struct Bloco {
    int index;                  // Índice do bloco
    time_t timestamp;           // Timestamp do bloco
    Transacao transacao;        // Dados do voto
    char hash_anterior[65];     // Hash do bloco anterior
    char hash[65];              // Hash do bloco atual
    struct Bloco *proximo;      // Ponteiro para o próximo bloco
} Bloco;

// Estrutura do Blockchain
typedef struct {
    Bloco *inicio;              // Ponteiro para o bloco inicial (Gênesis)
    int tamanho;                // Número de blocos no blockchain
} Blockchain;

Bloco* criar_bloco(Blockchain *blockchain, Transacao transacao) {
    Bloco *novo_bloco = (Bloco *)malloc(sizeof(Bloco));
    novo_bloco->index = blockchain->tamanho;
    novo_bloco->timestamp = time(NULL);
    novo_bloco->transacao = transacao;

    // Copiar o hash do bloco anterior
    Bloco *ultimo = blockchain->inicio;
    while (ultimo->proximo != NULL) {
        ultimo = ultimo->proximo;
    }
    strcpy(novo_bloco->hash_anterior, ultimo->hash);

    // Criar uma string com os dados do bloco para calcular o hash
    char dados_para_hash[256];
    snprintf(dados_para_hash, sizeof(dados_para_hash), "%d%s%s%s%ld",
             novo_bloco->index, novo_bloco->transacao.chave, novo_bloco->transacao.candidato,
             novo_bloco->hash_anterior, novo_bloco->timestamp);

    // Gerar o hash do bloco atual
    calcular_hash(dados_para_hash, novo_bloco->hash);

    novo_bloco->proximo = NULL;

    // Atualizar o blockchain
    ultimo->proximo = novo_bloco;
    blockchain->tamanho++;

    return novo_bloco;
}


void exibir_blockchain(Blockchain *blockchain) {
    Bloco *atual = blockchain->inicio;
    while (atual != NULL) {
        printf("Bloco #%d\n", atual->index);
        printf("Timestamp: %s", ctime(&atual->timestamp));
        printf("Chave: %s\n", atual->transacao.chave);
        printf("Candidato: %s\n", atual->transacao.candidato);
        printf("Hash Anterior: %s\n", atual->hash_anterior);
        printf("Hash Atual: %s\n", atual->hash);
        printf("-----------------------\n");
        atual = atual->proximo;
    }
}

// Função para calcular o hash SHA-256
void calcular_hash(const char *entrada, char *saida) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    // Inicializa o contexto SHA-256
    SHA256_Init(&sha256);
    // Atualiza o contexto com os dados de entrada
    SHA256_Update(&sha256, entrada, strlen(entrada));
    // Finaliza o cálculo do hash
    SHA256_Final(hash, &sha256);

    // Converte o hash para uma string hexadecimal
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(saida + (i * 2), "%02x", hash[i]);
    }
    saida[64] = '\0'; // Certifique-se de terminar a string com '\0'
}
