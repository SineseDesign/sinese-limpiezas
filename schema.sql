-- Sinese Limpiezas · esquema y funciones (Supabase / Postgres)
-- Las tablas no son accesibles con la clave pública: todo pasa por funciones que comprueban la sesión.
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.personas (
  id serial primary key,
  nombre text unique not null,
  rol text not null check (rol in ('admin','encargada','limpiadora')),
  pin_hash text,
  fallos int not null default 0,
  bloqueado_hasta timestamptz,
  activo boolean not null default true
);
create table if not exists public.sesiones (
  token uuid primary key default gen_random_uuid(),
  persona_id int not null references public.personas(id) on delete cascade,
  creado timestamptz not null default now()
);
create table if not exists public.pisos (
  id serial primary key,
  nombre text unique not null,
  amenitiz text,
  sale text,
  entra text,
  min_prev int,
  max_prev int,
  otra_zona boolean not null default false,
  activo boolean not null default true
);
create table if not exists public.tareas (
  id bigserial primary key,
  fecha date not null,
  piso_id int not null references public.pisos(id),
  pax int,                -- null = por confirmar, 0 = ese día no entra nadie
  limpiadora_id int references public.personas(id),
  entro timestamptz,
  salgo timestamptz,
  nueva boolean not null default false,
  prox_fecha date,
  prox_pax int,
  creado timestamptz not null default now()
);
create index if not exists tareas_fecha_idx on public.tareas(fecha);
create table if not exists public.incidencias (
  id bigserial primary key,
  tarea_id bigint not null references public.tareas(id) on delete cascade,
  persona_id int references public.personas(id),
  texto text not null,
  creado timestamptz not null default now()
);
create table if not exists public.vacaciones (
  id serial primary key,
  persona_id int not null references public.personas(id) on delete cascade,
  desde date not null,
  hasta date not null
);
alter table public.personas enable row level security;
alter table public.sesiones enable row level security;
alter table public.pisos enable row level security;
alter table public.tareas enable row level security;
alter table public.incidencias enable row level security;
alter table public.vacaciones enable row level security;

create or replace function public._quien(p_token uuid) returns public.personas
language sql stable security definer set search_path = public as $$
  select p.* from sesiones s join personas p on p.id = s.persona_id
  where s.token = p_token and p.activo limit 1
$$;

create or replace function public._gestiona(p_rol text, p_piso int) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(p_rol = 'admin'
    or (p_rol = 'encargada' and not coalesce((select otra_zona from pisos where id = p_piso), true)), false)
$$;

create or replace function public.lista_personas() returns json
language sql stable security definer set search_path = public as $$
  select coalesce(json_agg(json_build_object('nombre', nombre, 'rol', rol, 'tiene_pin', pin_hash is not null)
    order by case rol when 'encargada' then 1 when 'limpiadora' then 2 else 3 end, nombre), '[]'::json)
  from personas where activo
$$;

create or replace function public.entrar(p_nombre text, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare p personas; t uuid;
begin
  select * into p from personas where nombre = p_nombre and activo;
  if not found then return json_build_object('error', 'Persona no encontrada'); end if;
  if p_pin is null or p_pin !~ '^[0-9]{4,8}$' then
    return json_build_object('error', 'El PIN debe tener entre 4 y 8 cifras'); end if;
  if p.bloqueado_hasta is not null and p.bloqueado_hasta > now() then
    return json_build_object('error', 'Demasiados intentos. Espera cinco minutos.'); end if;
  if p.pin_hash is null then
    update personas set pin_hash = crypt(p_pin, gen_salt('bf')), fallos = 0, bloqueado_hasta = null where id = p.id;
  elsif p.pin_hash <> crypt(p_pin, p.pin_hash) then
    update personas set fallos = fallos + 1,
      bloqueado_hasta = case when fallos + 1 >= 5 then now() + interval '5 minutes' else null end
    where id = p.id;
    return json_build_object('error', 'PIN incorrecto');
  else
    update personas set fallos = 0, bloqueado_hasta = null where id = p.id;
  end if;
  insert into sesiones(persona_id) values (p.id) returning token into t;
  return json_build_object('token', t, 'id', p.id, 'nombre', p.nombre, 'rol', p.rol);
end $$;

create or replace function public.salir(p_token uuid) returns json
language sql security definer set search_path = public as $$
  delete from sesiones where token = p_token; select json_build_object('ok', true)
$$;

create or replace function public.datos(p_token uuid, p_desde date, p_hasta date) returns json
language plpgsql stable security definer set search_path = public as $$
declare yo personas;
begin
  select * into yo from _quien(p_token);
  if yo.id is null then return json_build_object('error', 'sesion'); end if;
  return json_build_object(
    'yo', json_build_object('id', yo.id, 'nombre', yo.nombre, 'rol', yo.rol),
    'hoy', (now() at time zone 'Europe/Madrid')::date,
    'personas', (select coalesce(json_agg(json_build_object('id', id, 'nombre', nombre, 'rol', rol,
        'tiene_pin', pin_hash is not null) order by id), '[]'::json) from personas where activo),
    'pisos', (select coalesce(json_agg(json_build_object('id', id, 'nombre', nombre, 'sale', sale, 'entra', entra,
        'min', min_prev, 'max', max_prev, 'otra_zona', otra_zona) order by nombre), '[]'::json) from pisos where activo),
    'vacaciones', (select coalesce(json_agg(json_build_object('persona_id', persona_id, 'desde', desde, 'hasta', hasta)), '[]'::json)
        from vacaciones where hasta >= p_desde and desde <= p_hasta),
    'tareas', (select coalesce(json_agg(json_build_object('id', t.id, 'fecha', t.fecha, 'piso_id', t.piso_id, 'pax', t.pax,
        'limpiadora_id', t.limpiadora_id, 'entro', t.entro, 'salgo', t.salgo, 'nueva', t.nueva,
        'prox_fecha', t.prox_fecha, 'prox_pax', t.prox_pax,
        'inc', (select coalesce(json_agg(json_build_object('texto', i.texto, 'creado', i.creado,
            'quien', (select nombre from personas where id = i.persona_id)) order by i.creado), '[]'::json)
          from incidencias i where i.tarea_id = t.id)) order by t.fecha, t.id), '[]'::json)
      from tareas t join pisos z on z.id = t.piso_id
      where t.fecha between p_desde and p_hasta
        and (yo.rol = 'admin'
          or (yo.rol = 'encargada' and (not z.otra_zona or t.limpiadora_id = yo.id))
          or t.limpiadora_id = yo.id))
  );
end $$;

create or replace function public.editar_tarea(p_token uuid, p_tarea bigint, p_cambios jsonb) returns json
language plpgsql security definer set search_path = public as $$
declare yo personas; t tareas; v int;
begin
  select * into yo from _quien(p_token);
  if yo.id is null then return json_build_object('error', 'sesion'); end if;
  select * into t from tareas where id = p_tarea;
  if not found then return json_build_object('error', 'Esa limpieza ya no existe'); end if;
  if not _gestiona(yo.rol, t.piso_id) then return json_build_object('error', 'No tienes permiso'); end if;
  if p_cambios ? 'limpiadora_id' then
    v := (p_cambios->>'limpiadora_id')::int;
    if v is not null and not exists (select 1 from personas where id = v and activo and rol in ('limpiadora','encargada')) then
      return json_build_object('error', 'Persona no válida'); end if;
    update tareas set limpiadora_id = v where id = p_tarea;
  end if;
  if p_cambios ? 'pax' then
    v := (p_cambios->>'pax')::int;
    if v is not null and (v < 0 or v > 30) then return json_build_object('error', 'Número de personas no válido'); end if;
    update tareas set pax = v where id = p_tarea;
  end if;
  if p_cambios ? 'fecha' then
    if t.entro is not null then return json_build_object('error', 'Esa limpieza ya está empezada'); end if;
    update tareas set fecha = (p_cambios->>'fecha')::date where id = p_tarea;
  end if;
  return json_build_object('ok', true);
end $$;

create or replace function public.nueva_tarea(p_token uuid, p_fecha date, p_piso int, p_pax int, p_limpiadora int) returns json
language plpgsql security definer set search_path = public as $$
declare yo personas; n bigint;
begin
  select * into yo from _quien(p_token);
  if yo.id is null then return json_build_object('error', 'sesion'); end if;
  if not exists (select 1 from pisos where id = p_piso and activo) then return json_build_object('error', 'Piso no válido'); end if;
  if not _gestiona(yo.rol, p_piso) then return json_build_object('error', 'No tienes permiso'); end if;
  if p_pax is not null and (p_pax < 0 or p_pax > 30) then return json_build_object('error', 'Número de personas no válido'); end if;
  if p_limpiadora is not null and not exists (select 1 from personas where id = p_limpiadora and activo and rol in ('limpiadora','encargada')) then
    return json_build_object('error', 'Persona no válida'); end if;
  if exists (select 1 from tareas where fecha = p_fecha and piso_id = p_piso) then
    return json_build_object('error', 'Ese piso ya está en ese día'); end if;
  insert into tareas(fecha, piso_id, pax, limpiadora_id, nueva) values (p_fecha, p_piso, p_pax, p_limpiadora, true) returning id into n;
  return json_build_object('ok', true, 'id', n);
end $$;

create or replace function public.quitar_tarea(p_token uuid, p_tarea bigint) returns json
language plpgsql security definer set search_path = public as $$
declare yo personas; t tareas;
begin
  select * into yo from _quien(p_token);
  if yo.id is null then return json_build_object('error', 'sesion'); end if;
  select * into t from tareas where id = p_tarea;
  if not found then return json_build_object('ok', true); end if;
  if not _gestiona(yo.rol, t.piso_id) then return json_build_object('error', 'No tienes permiso'); end if;
  if t.entro is not null then return json_build_object('error', 'Esa limpieza ya está empezada'); end if;
  delete from tareas where id = p_tarea;
  return json_build_object('ok', true);
end $$;

create or replace function public.marcar(p_token uuid, p_tarea bigint, p_accion text) returns json
language plpgsql security definer set search_path = public as $$
declare yo personas; t tareas; jefe boolean;
begin
  select * into yo from _quien(p_token);
  if yo.id is null then return json_build_object('error', 'sesion'); end if;
  select * into t from tareas where id = p_tarea;
  if not found then return json_build_object('error', 'Esa limpieza ya no existe'); end if;
  jefe := yo.rol in ('admin', 'encargada');
  if not jefe and t.limpiadora_id is distinct from yo.id then return json_build_object('error', 'Ese piso no es tuyo'); end if;
  if not jefe and t.fecha <> (now() at time zone 'Europe/Madrid')::date then
    return json_build_object('error', 'Solo se puede marcar el día de la limpieza'); end if;
  if p_accion = 'entro' then
    update tareas set entro = coalesce(entro, now()) where id = p_tarea;
  elsif p_accion = 'salgo' then
    if t.entro is null then return json_build_object('error', 'Primero marca la entrada'); end if;
    update tareas set salgo = coalesce(salgo, now()) where id = p_tarea;
  elsif p_accion = 'corregir' then
    update tareas set entro = null, salgo = null where id = p_tarea;
  else
    return json_build_object('error', 'Acción no válida');
  end if;
  return json_build_object('ok', true);
end $$;

create or replace function public.incidencia(p_token uuid, p_tarea bigint, p_texto text) returns json
language plpgsql security definer set search_path = public as $$
declare yo personas; t tareas; x text;
begin
  select * into yo from _quien(p_token);
  if yo.id is null then return json_build_object('error', 'sesion'); end if;
  select * into t from tareas where id = p_tarea;
  if not found then return json_build_object('error', 'Esa limpieza ya no existe'); end if;
  if yo.rol = 'limpiadora' and t.limpiadora_id is distinct from yo.id then return json_build_object('error', 'Ese piso no es tuyo'); end if;
  x := btrim(coalesce(p_texto, ''));
  if length(x) = 0 or length(x) > 500 then return json_build_object('error', 'Escribe la incidencia (máximo 500 letras)'); end if;
  insert into incidencias(tarea_id, persona_id, texto) values (p_tarea, yo.id, x);
  return json_build_object('ok', true);
end $$;

create or replace function public.reset_pin(p_token uuid, p_persona int) returns json
language plpgsql security definer set search_path = public as $$
declare yo personas;
begin
  select * into yo from _quien(p_token);
  if yo.id is null then return json_build_object('error', 'sesion'); end if;
  if yo.rol <> 'admin' then return json_build_object('error', 'No tienes permiso'); end if;
  update personas set pin_hash = null, fallos = 0, bloqueado_hasta = null where id = p_persona;
  delete from sesiones where persona_id = p_persona;
  return json_build_object('ok', true);
end $$;

revoke execute on function public._quien(uuid) from public, anon, authenticated;
revoke execute on function public._gestiona(text, int) from public, anon, authenticated;
grant execute on function public.lista_personas() to anon;
grant execute on function public.entrar(text, text) to anon;
grant execute on function public.salir(uuid) to anon;
grant execute on function public.datos(uuid, date, date) to anon;
grant execute on function public.editar_tarea(uuid, bigint, jsonb) to anon;
grant execute on function public.nueva_tarea(uuid, date, int, int, int) to anon;
grant execute on function public.quitar_tarea(uuid, bigint) to anon;
grant execute on function public.marcar(uuid, bigint, text) to anon;
grant execute on function public.incidencia(uuid, bigint, text) to anon;
grant execute on function public.reset_pin(uuid, int) to anon;
notify pgrst, 'reload schema';
