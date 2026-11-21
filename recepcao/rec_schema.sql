-- ERPPA Recepção · esquema do banco (v1) — rode inteiro no SQL Editor do Supabase
-- =====================================================================
-- ERPPA · Sistema de Recepção · Banco de dados (Supabase)  v1
-- 100% ADITIVO: só cria objetos rec_* . Não altera nenhuma tabela existente.
-- Níveis: 1 = Equipe · 2 = Guest · 3 = Supervisor
-- Login por token (mesmo padrão do DP): RPCs SECURITY DEFINER + RLS por cabeçalho x-rec-token
-- =====================================================================
create extension if not exists pgcrypto with schema extensions;

-- ---------- Autenticação ----------
create table if not exists public.rec_usuarios(
  id uuid primary key default gen_random_uuid(),
  nome text not null,
  nivel int not null check (nivel between 1 and 3),
  senha_hash text not null,
  trocar_senha boolean not null default true,
  ativo boolean not null default true,
  criado_em timestamptz not null default now()
);
create unique index if not exists rec_usuarios_nome_uq on public.rec_usuarios (lower(nome));

create table if not exists public.rec_sessoes(
  token_hash text primary key,
  usuario_id uuid not null references public.rec_usuarios(id) on delete cascade,
  criado_em timestamptz not null default now(),
  expira_em timestamptz not null,
  ultimo_uso timestamptz not null default now()
);
create table if not exists public.rec_tentativas(
  id bigserial primary key,
  nome_lower text not null,
  criado_em timestamptz not null default now()
);
create index if not exists rec_tentativas_idx on public.rec_tentativas(nome_lower, criado_em);

alter table public.rec_usuarios enable row level security;
alter table public.rec_sessoes enable row level security;
alter table public.rec_tentativas enable row level security;
revoke all on public.rec_usuarios, public.rec_sessoes, public.rec_tentativas from anon, authenticated;
revoke all on sequence public.rec_tentativas_id_seq from anon, authenticated;

-- ---------- Funções de sessão (lidas pelas políticas RLS) ----------
create or replace function public.rec_token_hash() returns text
language sql stable set search_path = public, extensions as $$
  select encode(digest(coalesce(nullif(current_setting('request.headers', true),'')::json->>'x-rec-token',''),'sha256'),'hex')
$$;

create or replace function public.rec_uid() returns uuid
language sql stable security definer set search_path = public, extensions as $$
  select s.usuario_id from rec_sessoes s join rec_usuarios u on u.id=s.usuario_id
   where s.token_hash = rec_token_hash() and s.expira_em > now() and u.ativo
$$;
create or replace function public.rec_nivel() returns int
language sql stable security definer set search_path = public, extensions as $$
  select coalesce((select u.nivel from rec_sessoes s join rec_usuarios u on u.id=s.usuario_id
   where s.token_hash = rec_token_hash() and s.expira_em > now() and u.ativo),0)
$$;
create or replace function public.rec_nome() returns text
language sql stable security definer set search_path = public, extensions as $$
  select (select u.nome from rec_sessoes s join rec_usuarios u on u.id=s.usuario_id
   where s.token_hash = rec_token_hash() and s.expira_em > now() and u.ativo)
$$;
revoke all on function public.rec_uid(), public.rec_nivel(), public.rec_nome(), public.rec_token_hash() from public;
grant execute on function public.rec_uid(), public.rec_nivel(), public.rec_nome(), public.rec_token_hash() to anon, authenticated;

-- ---------- RPCs de login ----------
create or replace function public.rec_login(p_nome text, p_senha text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare u rec_usuarios; tok text; falhas int;
begin
  select count(*) into falhas from rec_tentativas where nome_lower=lower(trim(p_nome)) and criado_em > now()-interval '10 minutes';
  if falhas >= 5 then return json_build_object('ok',false,'erro','Muitas tentativas. Aguarde 10 minutos.'); end if;
  select * into u from rec_usuarios where lower(nome)=lower(trim(p_nome)) and ativo;
  if u.id is null or u.senha_hash <> crypt(p_senha, u.senha_hash) then
    insert into rec_tentativas(nome_lower) values (lower(trim(p_nome)));
    return json_build_object('ok',false,'erro','Usuário ou senha inválidos.');
  end if;
  delete from rec_tentativas where nome_lower=lower(trim(p_nome));
  delete from rec_sessoes where expira_em < now();
  tok := replace(gen_random_uuid()::text,'-','') || replace(gen_random_uuid()::text,'-','');
  insert into rec_sessoes(token_hash, usuario_id, expira_em) values (encode(digest(tok,'sha256'),'hex'), u.id, now()+interval '12 hours');
  return json_build_object('ok',true,'token',tok,'id',u.id,'nome',u.nome,'nivel',u.nivel,'trocar_senha',u.trocar_senha);
end $$;

create or replace function public.rec_sessao() returns json
language plpgsql security definer set search_path = public, extensions as $$
declare u rec_usuarios; h text := rec_token_hash();
begin
  select u2.* into u from rec_sessoes s join rec_usuarios u2 on u2.id=s.usuario_id
   where s.token_hash=h and s.expira_em>now() and u2.ativo;
  if u.id is null then return json_build_object('ok',false); end if;
  update rec_sessoes set ultimo_uso=now(), expira_em=now()+interval '12 hours' where token_hash=h;
  return json_build_object('ok',true,'id',u.id,'nome',u.nome,'nivel',u.nivel,'trocar_senha',u.trocar_senha);
end $$;

create or replace function public.rec_logout() returns void
language sql security definer set search_path = public, extensions as $$
  delete from rec_sessoes where token_hash = rec_token_hash()
$$;

create or replace function public.rec_trocar_senha(p_atual text, p_nova text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare uid uuid := rec_uid(); u rec_usuarios;
begin
  if uid is null then return json_build_object('ok',false,'erro','Sessão expirada.'); end if;
  select * into u from rec_usuarios where id=uid;
  if u.senha_hash <> crypt(p_atual, u.senha_hash) then return json_build_object('ok',false,'erro','Senha atual incorreta.'); end if;
  if length(coalesce(p_nova,'')) < 8 then return json_build_object('ok',false,'erro','A nova senha deve ter ao menos 8 caracteres.'); end if;
  if p_nova = p_atual then return json_build_object('ok',false,'erro','A nova senha deve ser diferente da atual.'); end if;
  update rec_usuarios set senha_hash=crypt(p_nova, gen_salt('bf')), trocar_senha=false where id=uid;
  return json_build_object('ok',true);
end $$;

-- ---------- Gestão de usuários (somente Supervisor) ----------
create or replace function public.rec_usuarios_listar() returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  if rec_nivel() < 3 then raise exception 'Acesso negado'; end if;
  return (select coalesce(json_agg(json_build_object('id',id,'nome',nome,'nivel',nivel,'ativo',ativo,'trocar_senha',trocar_senha) order by nivel desc, nome),'[]'::json) from rec_usuarios);
end $$;

create or replace function public.rec_usuario_criar(p_nome text, p_nivel int, p_senha text) returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  if rec_nivel() < 3 then raise exception 'Acesso negado'; end if;
  if length(trim(coalesce(p_nome,''))) < 3 then return json_build_object('ok',false,'erro','Informe o nome.'); end if;
  if p_nivel not between 1 and 3 then return json_build_object('ok',false,'erro','Perfil inválido.'); end if;
  if length(coalesce(p_senha,'')) < 6 then return json_build_object('ok',false,'erro','Senha provisória: mínimo 6 caracteres.'); end if;
  if exists(select 1 from rec_usuarios where lower(nome)=lower(trim(p_nome))) then return json_build_object('ok',false,'erro','Já existe usuário com esse nome.'); end if;
  insert into rec_usuarios(nome,nivel,senha_hash,trocar_senha) values (trim(p_nome),p_nivel,crypt(p_senha,gen_salt('bf')),true);
  return json_build_object('ok',true);
end $$;

create or replace function public.rec_usuario_alterar(p_id uuid, p_nivel int, p_ativo boolean) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare sups int;
begin
  if rec_nivel() < 3 then raise exception 'Acesso negado'; end if;
  if p_nivel not between 1 and 3 then return json_build_object('ok',false,'erro','Perfil inválido.'); end if;
  select count(*) into sups from rec_usuarios where nivel=3 and ativo and id<>p_id;
  if sups = 0 and (p_nivel<3 or not p_ativo) then return json_build_object('ok',false,'erro','Deve existir ao menos um Supervisor ativo.'); end if;
  update rec_usuarios set nivel=p_nivel, ativo=p_ativo where id=p_id;
  if not p_ativo then delete from rec_sessoes where usuario_id=p_id; end if;
  return json_build_object('ok',true);
end $$;

create or replace function public.rec_usuario_redefinir(p_id uuid, p_senha text) returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  if rec_nivel() < 3 then raise exception 'Acesso negado'; end if;
  if length(coalesce(p_senha,'')) < 6 then return json_build_object('ok',false,'erro','Mínimo 6 caracteres.'); end if;
  update rec_usuarios set senha_hash=crypt(p_senha,gen_salt('bf')), trocar_senha=true where id=p_id;
  delete from rec_sessoes where usuario_id=p_id;
  return json_build_object('ok',true);
end $$;

create or replace function public.rec_usuario_excluir(p_id uuid) returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  if rec_nivel() < 3 then raise exception 'Acesso negado'; end if;
  if p_id = rec_uid() then return json_build_object('ok',false,'erro','Você não pode excluir o próprio usuário.'); end if;
  if (select nivel from rec_usuarios where id=p_id)=3 and (select count(*) from rec_usuarios where nivel=3 and ativo and id<>p_id)=0 then
    return json_build_object('ok',false,'erro','Deve existir ao menos um Supervisor ativo.'); end if;
  delete from rec_usuarios where id=p_id;
  return json_build_object('ok',true);
end $$;

-- Lista de nomes da equipe (para responsáveis / quem leu) — qualquer nível logado
create or replace function public.rec_equipe_lista() returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  if rec_nivel() < 1 then raise exception 'Acesso negado'; end if;
  return (select coalesce(json_agg(json_build_object('id',id,'nome',nome,'nivel',nivel) order by nome),'[]'::json) from rec_usuarios where ativo);
end $$;

do $$ declare f text; begin
 foreach f in array array['rec_login(text,text)','rec_sessao()','rec_logout()','rec_trocar_senha(text,text)','rec_usuarios_listar()','rec_usuario_criar(text,int,text)','rec_usuario_alterar(uuid,int,boolean)','rec_usuario_redefinir(uuid,text)','rec_usuario_excluir(uuid)','rec_equipe_lista()'] loop
  execute format('revoke all on function public.%s from public', f);
  execute format('grant execute on function public.%s to anon, authenticated', f);
 end loop; end $$;
-- =====================================================================
-- Tabelas de dados da Recepção + RLS por nível + histórico/notificações
-- =====================================================================
create or replace function public.rec_modulo_min(p text) returns int language sql immutable as $$
  select case p
    when 'rec_mural' then 1 when 'rec_plantoes' then 1 when 'rec_pendencias' then 1 when 'rec_conhecimento' then 1
    when 'rec_achados' then 1 when 'rec_solicitacoes' then 1 when 'rec_cortesias' then 1 when 'rec_agenda' then 1
    when 'rec_avaliacoes' then 2 when 'rec_respostas' then 2 when 'rec_reclamacoes' then 2
    when 'rec_acompanhamentos' then 2 when 'rec_recuperacoes' then 2
    else 3 end
$$;
grant execute on function public.rec_modulo_min(text) to anon, authenticated;

-- ---------- EQUIPE ----------
create table if not exists public.rec_mural(
  id uuid primary key default gen_random_uuid(),
  titulo text not null, texto text not null default '', categoria text not null default 'Aviso',
  fixado boolean not null default false, expira_em date, leitura_obrigatoria boolean not null default false,
  ativo boolean not null default true,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());
create table if not exists public.rec_mural_leituras(
  id uuid primary key default gen_random_uuid(),
  mural_id uuid not null references public.rec_mural(id) on delete cascade,
  usuario_id uuid not null default public.rec_uid(), nome text default public.rec_nome(), lido_em timestamptz not null default now(),
  unique(mural_id, usuario_id));

create table if not exists public.rec_plantoes(
  id uuid primary key default gen_random_uuid(),
  data date not null default current_date, turno text not null default 'Manhã',
  entrega_por text, recebe_por text, resumo text default '', ocorrencias text default '', pendencias text default '',
  hospedes_acompanhar text default '', cortesias_entregar text default '', aguardando_setores text default '',
  atencao_proximo text default '',
  status text not null default 'aberto' check (status in ('aberto','fechado','confirmado')),
  confirmado_por text, confirmado_em timestamptz,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());

create table if not exists public.rec_pendencias(
  id uuid primary key default gen_random_uuid(),
  titulo text not null, descricao text default '', prioridade text not null default 'Normal',
  status text not null default 'Pendente' check (status in ('Pendente','Em andamento','Aguardando terceiros','Concluída','Cancelada')),
  responsavel text, atribuida_equipe boolean not null default true, prazo date, lembrete_em timestamptz,
  plantao_id uuid references public.rec_plantoes(id) on delete set null, concluida_em timestamptz,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());

create table if not exists public.rec_conhecimento(
  id uuid primary key default gen_random_uuid(),
  titulo text not null, categoria text not null default 'Procedimentos', conteudo text not null default '',
  palavras_chave text default '', versao int not null default 1, leitura_obrigatoria boolean not null default false, ativo boolean not null default true,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());
create table if not exists public.rec_conhecimento_versoes(
  id uuid primary key default gen_random_uuid(),
  doc_id uuid not null references public.rec_conhecimento(id) on delete cascade, versao int not null,
  titulo text, conteudo text, autor text, criado_em timestamptz not null default now());
create table if not exists public.rec_conhecimento_leituras(
  id uuid primary key default gen_random_uuid(),
  doc_id uuid not null references public.rec_conhecimento(id) on delete cascade, versao int not null,
  usuario_id uuid not null default public.rec_uid(), nome text default public.rec_nome(), lido_em timestamptz not null default now(),
  unique(doc_id, versao, usuario_id));
create table if not exists public.rec_favoritos(
  id uuid primary key default gen_random_uuid(),
  doc_id uuid not null references public.rec_conhecimento(id) on delete cascade,
  usuario_id uuid not null default public.rec_uid(), unique(doc_id, usuario_id));

create table if not exists public.rec_achados(
  id uuid primary key default gen_random_uuid(),
  gov_id text unique,                       -- id do registro em gov_achados_perdidos (Governança), se veio de lá
  origem text not null default 'Recepção', item text not null, local_encontrado text, data_achado date default current_date, encontrado_por text,
  status text not null default 'Encontrado' check (status in ('Encontrado','Armazenado','Hóspede identificado','Aguardando retirada','Em processo de devolução','Devolvido','Encerrado')),
  hospede text, uh text, contato text, local_guarda text, retirada_prevista date, devolvido_para text, devolvido_em date, obs text,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());

create table if not exists public.rec_solicitacoes(
  id uuid primary key default gen_random_uuid(),
  destino text not null default 'Governança' check (destino in ('Governança','A&B','Administrativo','Guest Relations','Manutenção','Outros')),
  titulo text not null, descricao text default '', uh text, prioridade text not null default 'Normal',
  status text not null default 'Aberta' check (status in ('Aberta','Em andamento','Concluída','Cancelada')),
  responsavel text, prazo date, manutencao_ref text, concluida_em timestamptz,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());

create table if not exists public.rec_cortesias(
  id uuid primary key default gen_random_uuid(),
  hospede text not null, uh text, tipo text not null default 'Cortesia', descricao text default '', motivo text default '',
  data_entrega date, acompanhamento_id uuid,
  status text not null default 'Solicitada' check (status in ('Solicitada','Aprovada','Recusada','Entregue')),
  aprovado_por text, aprovado_em timestamptz, entregue_por text, entregue_em timestamptz,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());

create table if not exists public.rec_agenda(
  id uuid primary key default gen_random_uuid(),
  titulo text not null, responsavel text, participantes text default '', observacao text default '',
  inicio timestamptz not null, fim timestamptz not null, cancelado boolean not null default false,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now(),
  check (fim > inicio));

-- ---------- GUEST ----------
create table if not exists public.rec_avaliacoes(
  id uuid primary key default gen_random_uuid(),
  origem text not null default 'Google' check (origem in ('Booking','Google','TripAdvisor','Amplifique.me','Outra')),
  hospede text, data_avaliacao date default current_date, nota numeric(4,1), nota_max numeric(4,1) not null default 5,
  titulo text, texto text not null default '', url text,
  status text not null default 'Nova' check (status in ('Nova','Em resposta','Respondida','Ignorada')),
  respondida_em timestamptz,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());
create table if not exists public.rec_respostas(
  id uuid primary key default gen_random_uuid(),
  avaliacao_id uuid not null references public.rec_avaliacoes(id) on delete cascade,
  tom text default 'Cordial', versao int not null default 1, texto text not null,
  status text not null default 'Rascunho' check (status in ('Rascunho','Aprovada','Publicada')),
  aprovado_por text, aprovado_em timestamptz,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());
create table if not exists public.rec_reclamacoes(
  id uuid primary key default gen_random_uuid(),
  hospede text not null, uh text, categoria text default 'Outros', descricao text not null default '', gravidade text not null default 'Média',
  avaliacao_id uuid references public.rec_avaliacoes(id) on delete set null,
  status text not null default 'Aberta' check (status in ('Aberta','Em tratamento','Resolvida','Encerrada')),
  responsavel text, prazo date, solucao text, resolvida_em timestamptz,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());
create table if not exists public.rec_acompanhamentos(
  id uuid primary key default gen_random_uuid(),
  hospede text not null, uh text, checkin date, checkout date, motivo text default 'Acompanhamento', observacoes text default '',
  status text not null default 'Ativo' check (status in ('Ativo','Concluído')),
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());
create table if not exists public.rec_recuperacoes(
  id uuid primary key default gen_random_uuid(),
  reclamacao_id uuid references public.rec_reclamacoes(id) on delete set null,
  hospede text not null, acao text not null, custo numeric(10,2) default 0, responsavel text, prazo date,
  status text not null default 'Planejada' check (status in ('Planejada','Em execução','Executada','Cancelada')),
  resultado text not null default 'Pendente' check (resultado in ('Pendente','Recuperado','Parcial','Não recuperado')),
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());

-- ---------- SUPERVISOR ----------
create table if not exists public.rec_ocorrencias(
  id uuid primary key default gen_random_uuid(),
  titulo text not null, descricao text default '', tipo text default 'Operacional', gravidade text not null default 'Média',
  envolvidos text, local text, data_ocorrencia date default current_date, confidencial boolean not null default false,
  status text not null default 'Aberta' check (status in ('Aberta','Em análise','Ação corretiva','Encerrada')),
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());
create table if not exists public.rec_acoes_corretivas(
  id uuid primary key default gen_random_uuid(),
  ocorrencia_id uuid references public.rec_ocorrencias(id) on delete set null,
  acao text not null, responsavel text, prazo date,
  status text not null default 'Pendente' check (status in ('Pendente','Em andamento','Concluída','Cancelada')),
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());
create table if not exists public.rec_checklists(
  id uuid primary key default gen_random_uuid(),
  nome text not null, itens jsonb not null default '[]'::jsonb, ativo boolean not null default true,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());
create table if not exists public.rec_auditorias(
  id uuid primary key default gen_random_uuid(),
  checklist_id uuid references public.rec_checklists(id) on delete set null, checklist_nome text,
  data date not null default current_date, auditor text, respostas jsonb not null default '[]'::jsonb,
  nota numeric(5,1), obs text,
  autor text default public.rec_nome(), criado_em timestamptz not null default now(), atualizado_em timestamptz not null default now());

-- ---------- COMPARTILHADO ----------
create table if not exists public.rec_comentarios(
  id uuid primary key default gen_random_uuid(),
  modulo text not null, ref_id text not null, texto text not null,
  autor text default public.rec_nome(), criado_em timestamptz not null default now());
create index if not exists rec_coment_idx on public.rec_comentarios(modulo, ref_id);
create table if not exists public.rec_historico(
  id bigserial primary key,
  modulo text not null, ref_id text not null, acao text not null, detalhe jsonb, autor text, criado_em timestamptz not null default now());
create index if not exists rec_hist_idx on public.rec_historico(modulo, ref_id);
create table if not exists public.rec_notificacoes(
  id uuid primary key default gen_random_uuid(),
  nivel_min int not null default 1, modulo text, ref_id text, titulo text not null, texto text, autor text, criado_em timestamptz not null default now());
create table if not exists public.rec_notif_lidas(
  notif_id uuid not null references public.rec_notificacoes(id) on delete cascade,
  usuario_id uuid not null default public.rec_uid(), lida_em timestamptz not null default now(),
  primary key(notif_id, usuario_id));

-- ---------- Triggers ----------
create or replace function public.rec_touch() returns trigger language plpgsql as $$
begin new.atualizado_em := now(); return new; end $$;

create or replace function public.rec_audit() returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare d jsonb; rid text; nv jsonb; ov jsonb;
begin
  if tg_op='DELETE' then
    insert into rec_historico(modulo,ref_id,acao,detalhe,autor) values (tg_table_name, (to_jsonb(old)->>'id'), 'excluído', null, rec_nome());
    return old;
  end if;
  nv := to_jsonb(new); rid := nv->>'id';
  if tg_op='INSERT' then
    insert into rec_historico(modulo,ref_id,acao,detalhe,autor) values (tg_table_name, rid, 'criado', jsonb_build_object('status',nv->>'status'), rec_nome());
  else
    ov := to_jsonb(old);
    select coalesce(jsonb_object_agg(key, value),'{}'::jsonb) into d from jsonb_each(nv) where key not in ('atualizado_em') and (ov->key) is distinct from value;
    if d <> '{}'::jsonb then insert into rec_historico(modulo,ref_id,acao,detalhe,autor) values (tg_table_name, rid, 'alterado', d, rec_nome()); end if;
  end if;
  return new;
end $$;

create or replace function public.rec_notifica() returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare nv jsonb := to_jsonb(new);
begin
  insert into rec_notificacoes(nivel_min, modulo, ref_id, titulo, texto, autor)
  values (tg_argv[0]::int, tg_table_name, nv->>'id', tg_argv[1] || coalesce(nv->>tg_argv[2],''), nv->>tg_argv[3], rec_nome());
  return new;
end $$;

-- Cortesia: só Guest/Supervisor aprovam/recusam
create or replace function public.rec_cortesia_guard() returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  if tg_op='INSERT' then new.status := 'Solicitada'; new.aprovado_por:=null; new.aprovado_em:=null; return new; end if;
  if new.status in ('Aprovada','Recusada') and old.status is distinct from new.status then
    if rec_nivel() < 2 then raise exception 'Somente Guest ou Supervisor aprovam cortesias'; end if;
    new.aprovado_por := rec_nome(); new.aprovado_em := now();
  end if;
  if new.status='Entregue' and old.status is distinct from 'Entregue' then
    if old.status <> 'Aprovada' then raise exception 'A cortesia precisa estar aprovada antes da entrega'; end if;
    new.entregue_por := coalesce(new.entregue_por, rec_nome()); new.entregue_em := now();
  end if;
  return new;
end $$;

-- Plantão: confirmação de recebimento
create or replace function public.rec_plantao_guard() returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  if tg_op='UPDATE' and new.status='confirmado' and old.status is distinct from 'confirmado' then
    if old.status <> 'fechado' then raise exception 'Feche o plantão antes de confirmar o recebimento'; end if;
    new.confirmado_por := rec_nome(); new.confirmado_em := now();
  end if;
  if tg_op='UPDATE' and old.status in ('fechado','confirmado') and new.status = 'aberto' and rec_nivel()<3 then
    raise exception 'Somente o Supervisor reabre um plantão fechado';
  end if;
  return new;
end $$;

-- Agenda: impede sobreposição
create or replace function public.rec_agenda_guard() returns trigger language plpgsql as $$
begin
  if not new.cancelado and exists(select 1 from rec_agenda a where not a.cancelado and a.id<>new.id and a.inicio < new.fim and a.fim > new.inicio) then
    raise exception 'Conflito: já existe reunião agendada nesse horário';
  end if;
  return new;
end $$;

-- Conhecimento: versionamento automático
create or replace function public.rec_conhecimento_ver() returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  if tg_op='INSERT' then
    insert into rec_conhecimento_versoes(doc_id,versao,titulo,conteudo,autor) values (new.id,new.versao,new.titulo,new.conteudo,rec_nome());
  elsif new.conteudo is distinct from old.conteudo or new.titulo is distinct from old.titulo then
    new.versao := old.versao + 1;
    insert into rec_conhecimento_versoes(doc_id,versao,titulo,conteudo,autor) values (new.id,new.versao,new.titulo,new.conteudo,rec_nome());
  end if;
  return new;
end $$;
create or replace function public.rec_conhecimento_ver_ins() returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  insert into rec_conhecimento_versoes(doc_id,versao,titulo,conteudo,autor) values (new.id,new.versao,new.titulo,new.conteudo,rec_nome());
  return new;
end $$;

-- Aplica atualizado_em, histórico, RLS e grants em lote
do $$
declare t record;
begin
  for t in select * from (values
    ('rec_mural',1,2,3),('rec_plantoes',1,1,3),('rec_pendencias',1,1,3),('rec_conhecimento',1,2,3),
    ('rec_achados',1,1,3),('rec_solicitacoes',1,1,3),('rec_cortesias',1,1,3),('rec_agenda',1,3,3),
    ('rec_avaliacoes',2,2,3),('rec_respostas',2,2,3),('rec_reclamacoes',2,2,3),('rec_acompanhamentos',2,2,3),('rec_recuperacoes',2,2,3),
    ('rec_ocorrencias',3,3,3),('rec_acoes_corretivas',3,3,3),('rec_checklists',3,3,3),('rec_auditorias',3,3,3)
  ) as x(nome,rd,wr,dl)
  loop
    execute format('alter table public.%I enable row level security', t.nome);
    execute format('drop policy if exists rec_sel on public.%I', t.nome);
    execute format('drop policy if exists rec_ins on public.%I', t.nome);
    execute format('drop policy if exists rec_upd on public.%I', t.nome);
    execute format('drop policy if exists rec_del on public.%I', t.nome);
    execute format('create policy rec_sel on public.%I for select to anon, authenticated using ((select public.rec_nivel()) >= %s)', t.nome, t.rd);
    execute format('create policy rec_ins on public.%I for insert to anon, authenticated with check ((select public.rec_nivel()) >= %s)', t.nome, t.wr);
    execute format('create policy rec_upd on public.%I for update to anon, authenticated using ((select public.rec_nivel()) >= %s) with check ((select public.rec_nivel()) >= %s)', t.nome, t.wr, t.wr);
    execute format('create policy rec_del on public.%I for delete to anon, authenticated using ((select public.rec_nivel()) >= %s)', t.nome, t.dl);
    execute format('grant select, insert, update, delete on public.%I to anon, authenticated', t.nome);
    execute format('drop trigger if exists rec_t_touch on public.%I', t.nome);
    execute format('create trigger rec_t_touch before update on public.%I for each row execute function public.rec_touch()', t.nome);
    execute format('drop trigger if exists rec_t_audit on public.%I', t.nome);
    execute format('create trigger rec_t_audit after insert or update or delete on public.%I for each row execute function public.rec_audit()', t.nome);
  end loop;
end $$;

-- Políticas específicas (tabelas auxiliares)
do $$
declare p record;
begin
  -- leituras de mural / conhecimento / favoritos / lidas: cada um grava a própria; Guest+ vê todas
  for p in select unnest(array['rec_mural_leituras','rec_conhecimento_leituras']) as n loop
    execute format('alter table public.%I enable row level security', p.n);
    execute format('drop policy if exists rec_sel on public.%I', p.n); execute format('drop policy if exists rec_ins on public.%I', p.n);
    execute format('create policy rec_sel on public.%I for select to anon, authenticated using ((select public.rec_nivel())>=2 or usuario_id=(select public.rec_uid()))', p.n);
    execute format('create policy rec_ins on public.%I for insert to anon, authenticated with check ((select public.rec_nivel())>=1 and usuario_id=(select public.rec_uid()))', p.n);
    execute format('grant select, insert on public.%I to anon, authenticated', p.n);
  end loop;
  alter table public.rec_favoritos enable row level security;
  drop policy if exists rec_all on public.rec_favoritos;
  create policy rec_all on public.rec_favoritos for all to anon, authenticated using (usuario_id=(select public.rec_uid())) with check (usuario_id=(select public.rec_uid()));
  grant select, insert, delete on public.rec_favoritos to anon, authenticated;

  alter table public.rec_conhecimento_versoes enable row level security;
  drop policy if exists rec_sel on public.rec_conhecimento_versoes;
  create policy rec_sel on public.rec_conhecimento_versoes for select to anon, authenticated using ((select public.rec_nivel())>=1);
  grant select on public.rec_conhecimento_versoes to anon, authenticated;

  alter table public.rec_comentarios enable row level security;
  drop policy if exists rec_sel on public.rec_comentarios; drop policy if exists rec_ins on public.rec_comentarios; drop policy if exists rec_del on public.rec_comentarios;
  create policy rec_sel on public.rec_comentarios for select to anon, authenticated using ((select public.rec_nivel()) >= public.rec_modulo_min(modulo));
  create policy rec_ins on public.rec_comentarios for insert to anon, authenticated with check ((select public.rec_nivel()) >= public.rec_modulo_min(modulo));
  create policy rec_del on public.rec_comentarios for delete to anon, authenticated using ((select public.rec_nivel())>=3);
  grant select, insert, delete on public.rec_comentarios to anon, authenticated;

  alter table public.rec_historico enable row level security;
  drop policy if exists rec_sel on public.rec_historico;
  create policy rec_sel on public.rec_historico for select to anon, authenticated using ((select public.rec_nivel()) >= public.rec_modulo_min(modulo));
  grant select on public.rec_historico to anon, authenticated;

  alter table public.rec_notificacoes enable row level security;
  drop policy if exists rec_sel on public.rec_notificacoes; drop policy if exists rec_ins on public.rec_notificacoes;
  create policy rec_sel on public.rec_notificacoes for select to anon, authenticated using ((select public.rec_nivel()) >= nivel_min);
  create policy rec_ins on public.rec_notificacoes for insert to anon, authenticated with check ((select public.rec_nivel())>=3);
  grant select, insert on public.rec_notificacoes to anon, authenticated;

  alter table public.rec_notif_lidas enable row level security;
  drop policy if exists rec_all on public.rec_notif_lidas;
  create policy rec_all on public.rec_notif_lidas for all to anon, authenticated using (usuario_id=(select public.rec_uid())) with check (usuario_id=(select public.rec_uid()));
  grant select, insert, delete on public.rec_notif_lidas to anon, authenticated;
end $$;
revoke all on sequence public.rec_historico_id_seq from anon, authenticated;

-- Triggers de regra de negócio e notificações
drop trigger if exists rec_t_cortesia on public.rec_cortesias;
create trigger rec_t_cortesia before insert or update on public.rec_cortesias for each row execute function public.rec_cortesia_guard();
drop trigger if exists rec_t_plantao on public.rec_plantoes;
create trigger rec_t_plantao before update on public.rec_plantoes for each row execute function public.rec_plantao_guard();
drop trigger if exists rec_t_agenda on public.rec_agenda;
create trigger rec_t_agenda before insert or update on public.rec_agenda for each row execute function public.rec_agenda_guard();
drop trigger if exists rec_t_ver on public.rec_conhecimento;
create trigger rec_t_ver before update on public.rec_conhecimento for each row execute function public.rec_conhecimento_ver();
drop trigger if exists rec_t_ver_ins on public.rec_conhecimento;
create trigger rec_t_ver_ins after insert on public.rec_conhecimento for each row execute function public.rec_conhecimento_ver_ins();

drop trigger if exists rec_n_mural on public.rec_mural;
create trigger rec_n_mural after insert on public.rec_mural for each row execute function public.rec_notifica(1,'Mural: ','titulo','categoria');
drop trigger if exists rec_n_sol on public.rec_solicitacoes;
create trigger rec_n_sol after insert on public.rec_solicitacoes for each row execute function public.rec_notifica(1,'Solicitação: ','titulo','destino');
drop trigger if exists rec_n_cort on public.rec_cortesias;
create trigger rec_n_cort after insert on public.rec_cortesias for each row execute function public.rec_notifica(2,'Cortesia aguardando aprovação: ','hospede','tipo');
drop trigger if exists rec_n_recl on public.rec_reclamacoes;
create trigger rec_n_recl after insert on public.rec_reclamacoes for each row execute function public.rec_notifica(2,'Reclamação: ','hospede','categoria');
drop trigger if exists rec_n_ocor on public.rec_ocorrencias;
create trigger rec_n_ocor after insert on public.rec_ocorrencias for each row execute function public.rec_notifica(3,'Ocorrência: ','titulo','gravidade');
