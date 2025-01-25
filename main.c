#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include "mongoose.h"

#define MAX_USUARIOS 100  // Número máximo de usuários

typedef struct {
    char cpf[12];       // CPF do usuário (11 dígitos + '\0')
    char senha[20];     // Senha do usuário
} Usuario;


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
    int nonce;                  // Valor para Proof-of-Work
    struct Bloco *proximo;      // Ponteiro para o próximo bloco
} Bloco;


// Estrutura do Blockchain
typedef struct {
    Bloco *inicio;              // Ponteiro para o bloco inicial (Gênesis)
    int tamanho;                // Número de blocos no blockchain
} Blockchain;
// Lista de usuários registrados
Usuario usuarios[MAX_USUARIOS];
int num_usuarios = 0;

// Lista de CPFs que já votaram
char cpfs_votados[MAX_USUARIOS][12];
int num_votos = 0;
Blockchain *blockchain;
int dificuldade = 4;
// Não gosto da ideia de variáveis globais, mas estou sem tempo ultimamente :]

void adicionar_usuario(const char *, const char *);
bool autenticar_usuario(const char *, const char *);
bool verificar_cpf_votado(const char *);
void registrar_cpf(const char *);

void votar(Blockchain *, const char *, const char *, const char *, int );
Bloco* criar_bloco(Blockchain *, Transacao , int );
void exibir_blockchain(Blockchain *blockchain);
void calcular_hash(const char *, char *);
bool validar_blockchain(Blockchain *);
void minerar_bloco(Bloco *, int );

evento_http(struct mg_connection *, int , void *, void *);
void processar_votar(struct mg_http_message *, struct mg_connection *);
void processar_blockchain(struct mg_connection *);
void processar_validar(struct mg_connection *);
static void evento_http(struct mg_connection *, int , void *, void *);

int main() {
    // Inicializar blockchain e registrar alguns usuários para teste
    blockchain = inicializar_blockchain();
    adicionar_usuario("12345678901", "senha123");
    adicionar_usuario("98765432100", "minhasenha");

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);

    // Iniciar o servidor na porta 8080
    const char *url = "http://0.0.0.0:8080";
    printf("Servidor iniciado em %s\n", url);
    mg_http_listen(&mgr, url, evento_http, NULL);

    // Loop do servidor
    while (true) {
        mg_mgr_poll(&mgr, 1000);
    }

    mg_mgr_free(&mgr);
    return 0;
}
// Função para processar /votar
void processar_votar(struct mg_http_message *hm, struct mg_connection *c) {
    char cpf[12], senha[20], candidato[20];
    mg_http_get_var(&hm->body, "cpf", cpf, sizeof(cpf));
    mg_http_get_var(&hm->body, "senha", senha, sizeof(senha));
    mg_http_get_var(&hm->body, "candidato", candidato, sizeof(candidato));

    if (!autenticar_usuario(cpf, senha)) {
        mg_http_reply(c, 401, "Content-Type: text/plain\r\n", "Autenticação falhou\n");
        return;
    }

    if (verificar_cpf_votado(cpf)) {
        mg_http_reply(c, 403, "Content-Type: text/plain\r\n", "CPF já votou\n");
        return;
    }

    Transacao transacao;
    strcpy(transacao.chave, cpf); // CPF como chave
    strcpy(transacao.candidato, candidato);
    criar_bloco(blockchain, transacao, dificuldade);
    registrar_cpf(cpf);

    mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "Voto registrado com sucesso\n");
}

// Função para processar /blockchain
void processar_blockchain(struct mg_connection *c) {
    Bloco *atual = blockchain->inicio;
    char resposta[1024] = "[";

    while (atual != NULL) {
        char bloco[256];
        snprintf(bloco, sizeof(bloco),
                 "{\"index\":%d,\"cpf\":\"%s\",\"candidato\":\"%s\",\"hash\":\"%s\"},",
                 atual->index, atual->transacao.chave, atual->transacao.candidato, atual->hash);
        strcat(resposta, bloco);
        atual = atual->proximo;
    }

    // Remover a última vírgula e fechar o JSON
    if (resposta[strlen(resposta) - 1] == ',') {
        resposta[strlen(resposta) - 1] = '\0';
    }
    strcat(resposta, "]");

    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", resposta);
}

// Função para processar /validar
void processar_validar(struct mg_connection *c) {
    if (validar_blockchain(blockchain)) {
        mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "Blockchain válido\n");
    } else {
        mg_http_reply(c, 400, "Content-Type: text/plain\r\n", "Blockchain inválido\n");
    }
}

// Função principal do servidor HTTP
static void evento_http(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;

        if (mg_http_match_uri(hm, "/votar")) {
            processar_votar(hm, c);
        } else if (mg_http_match_uri(hm, "/blockchain")) {
            processar_blockchain(c);
        } else if (mg_http_match_uri(hm, "/validar")) {
            processar_validar(c);
        } else {
            mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "Endpoint não encontrado\n");
        }
    }
}
void adicionar_usuario(const char *cpf, const char *senha) {
    if (num_usuarios < MAX_USUARIOS) {
        strcpy(usuarios[num_usuarios].cpf, cpf);
        strcpy(usuarios[num_usuarios].senha, senha);
        num_usuarios++;
    } else {
        printf("Erro: número máximo de usuários atingido.\n");
    }
}

bool autenticar_usuario(const char *cpf, const char *senha) {
    for (int i = 0; i < num_usuarios; i++) {
        if (strcmp(usuarios[i].cpf, cpf) == 0 && strcmp(usuarios[i].senha, senha) == 0) {
            return true; // CPF e senha estão corretos
        }
    }
    return false; // Autenticação falhou
}

bool verificar_cpf_votado(const char *cpf) {
    for (int i = 0; i < num_votos; i++) {
        if (strcmp(cpfs_votados[i], cpf) == 0) {
            return true; // CPF já votou
        }
    }
    return false; // CPF ainda não votou
}

void registrar_cpf(const char *cpf) {
    if (num_votos < MAX_USUARIOS) {
        strcpy(cpfs_votados[num_votos], cpf);
        num_votos++;
    } else {
        printf("Erro: número máximo de votos atingido.\n");
    }
}

void votar(Blockchain *blockchain, const char *cpf, const char *senha, const char *candidato, int dificuldade) {
    // Verificar autenticação
    if (!autenticar_usuario(cpf, senha)) {
        printf("Autenticação falhou. CPF ou senha incorretos.\n");
        return;
    }

    // Verificar se o CPF já votou
    if (verificar_cpf_votado(cpf)) {
        printf("Erro: este CPF já realizou um voto.\n");
        return;
    }

    // Registrar o voto
    Transacao transacao;
    strcpy(transacao.chave, cpf);  // Para simplificação, usamos o CPF como chave no exemplo
    strcpy(transacao.candidato, candidato);

    criar_bloco(blockchain, transacao, dificuldade);

    // Registrar CPF como votado
    registrar_cpf(cpf);

    printf("Voto registrado com sucesso!\n");
}


Bloco* criar_bloco(Blockchain *blockchain, Transacao transacao, int dificuldade) {
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

    // Minerar o bloco
    minerar_bloco(novo_bloco, dificuldade);

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

#include <stdbool.h>

// Função para validar o blockchain
bool validar_blockchain(Blockchain *blockchain) {
    if (blockchain->inicio == NULL) {
        printf("Blockchain está vazio.\n");
        return false;
    }

    Bloco *atual = blockchain->inicio;
    while (atual->proximo != NULL) {
        // Recalcular o hash do bloco atual
        char hash_calculado[65];
        char dados_para_hash[256];
        snprintf(dados_para_hash, sizeof(dados_para_hash), "%d%s%s%s%ld",
                 atual->index, atual->transacao.chave, atual->transacao.candidato,
                 atual->hash_anterior, atual->timestamp);

        calcular_hash(dados_para_hash, hash_calculado);

        // Verificar se o hash armazenado no bloco é igual ao hash calculado
        if (strcmp(atual->hash, hash_calculado) != 0) {
            printf("Hash inválido no bloco #%d.\n", atual->index);
            return false;
        }

        // Verificar se o hash atual corresponde ao hash anterior do próximo bloco
        if (strcmp(atual->hash, atual->proximo->hash_anterior) != 0) {
            printf("Inconsistência entre os blocos #%d e #%d.\n", atual->index, atual->proximo->index);
            return false;
        }

        // Avançar para o próximo bloco
        atual = atual->proximo;
    }

    
void minerar_bloco(Bloco *bloco, int dificuldade) {
    char prefixo[dificuldade + 1];
    memset(prefixo, '0', dificuldade); // Prefixo de zeros
    prefixo[dificuldade] = '\0';

    bloco->nonce = 0;
    while (1) {
        // Gerar string com os dados para hash
        char dados_para_hash[256];
        snprintf(dados_para_hash, sizeof(dados_para_hash), "%d%s%s%s%ld%d",
                 bloco->index, bloco->transacao.chave, bloco->transacao.candidato,
                 bloco->hash_anterior, bloco->timestamp, bloco->nonce);

        // Calcular o hash
        calcular_hash(dados_para_hash, bloco->hash);

        // Verificar se o hash começa com o prefixo esperado
        if (strncmp(bloco->hash, prefixo, dificuldade) == 0) {
            printf("Bloco #%d minerado! Nonce: %d\n", bloco->index, bloco->nonce);
            printf("Hash: %s\n", bloco->hash);
            break;
        }

        bloco->nonce++;
    }
}

    printf("Blockchain válido.\n");
    return true;
}
