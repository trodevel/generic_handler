/*

Generic request handler.

Copyright (C) 2016 Sergey Kolevatov

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

*/

// $Revision: 12003 $ $Date:: 2019-09-16 #$ $Author: serge $

#include "handler.h"                // self

#include <typeindex>                // std::type_index
#include <unordered_map>

#include "utils/mutex_helper.h"      // MUTEX_SCOPE_LOCK
#include "utils/dummy_logger.h"      // dummy_log
#include "utils/utils_assert.h"      // ASSERT
#include "utils/chrono_epoch.h"     // utils::to_epoch

#include "generic_protocol/response_gen.h"              // generic_protocol::create_error_response

#include "session_manager/manager.h" // session_manager::Manager

#define MODULENAME      "generic_handler::Handler"

namespace generic_handler
{

Handler::Handler():
        sess_man_( nullptr ),
        user_man_( nullptr )
{
}

bool Handler::init(
        session_manager::Manager    * sess_man,
        user_manager::IIdConverter  * user_man )
{
    assert( user_man );

    MUTEX_SCOPE_LOCK( mutex_ );

    if( !sess_man )
        return false;

    sess_man_   = sess_man;
    user_man_   = user_man;

    return true;
}


generic_protocol::BackwardMessage* Handler::handle( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * req )
{
    MUTEX_SCOPE_LOCK( mutex_ );

    typedef Handler Type;

    typedef generic_protocol::BackwardMessage* (Type::*PPMF)( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * r );

#define HANDLER_MAP_ENTRY(_v)       { typeid( generic_protocol::_v ),        & Type::handle_##_v }

    static const std::unordered_map<std::type_index, PPMF> funcs =
    {
        HANDLER_MAP_ENTRY( AuthenticateRequest ),
        HANDLER_MAP_ENTRY( AuthenticateAltRequest ),
        HANDLER_MAP_ENTRY( CloseSessionRequest ),
        HANDLER_MAP_ENTRY( GetUserIdRequest ),
        HANDLER_MAP_ENTRY( GetSessionInfoRequest ),
    };

#undef HANDLER_MAP_ENTRY

    auto it = funcs.find( typeid( * req ) );

    if( it == funcs.end() )
    {
        dummy_log_fatal( MODULENAME, "handle: cannot cast request to known type - %s", typeid( *req ).name() );

        ASSERT( 0 );

        return nullptr;
    }

    return (this->*it->second)( session_user_id, req );
}

generic_protocol::BackwardMessage* Handler::handle_AuthenticateRequest( session_manager::user_id_t /*session_user_id*/, const generic_protocol::ForwardMessage * rr )
{
    auto & r = dynamic_cast< const generic_protocol::AuthenticateRequest &>( * rr );

    auto id = user_man_->convert_login_to_user_id( r.user_login, false );

    dummy_log_debug( MODULENAME, "handle: AuthenticateRequest: login %s, id %u", r.user_login.c_str(), id );

    std::string session_id;
    std::string error;

    if( sess_man_->authenticate( id, r.password, session_id, error ) )
    {
        return generic_protocol::create_autheticate_response( session_id );
    }

    return generic_protocol::create_error_response( generic_protocol::ErrorResponse::AUTHENTICATION_ERROR, error );
}

generic_protocol::BackwardMessage* Handler::handle_AuthenticateAltRequest( session_manager::user_id_t /*session_user_id*/, const generic_protocol::ForwardMessage * rr )
{
    auto & r = dynamic_cast< const generic_protocol::AuthenticateAltRequest &>( * rr );

    std::string session_id;
    std::string error;

    if( sess_man_->authenticate( r.user_id, r.password, session_id, error ) )
    {
        return generic_protocol::create_autheticate_response( session_id );
    }

    return generic_protocol::create_error_response( generic_protocol::ErrorResponse::AUTHENTICATION_ERROR, error );
}

generic_protocol::BackwardMessage* Handler::handle_CloseSessionRequest( session_manager::user_id_t /*session_user_id*/, const generic_protocol::ForwardMessage * rr )
{
    auto & r = dynamic_cast< const generic_protocol::CloseSessionRequest &>( * rr );

    std::string error;

    if( sess_man_->close_session( r.session_id, error ) )
    {
        return generic_protocol::create_close_session_response();
    }

    return generic_protocol::create_error_response( generic_protocol::ErrorResponse::RUNTIME_ERROR, error );
}

generic_protocol::BackwardMessage* Handler::handle_GetUserIdRequest( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * rr )
{
    auto & r = dynamic_cast< const generic_protocol::GetUserIdRequest &>( * rr );

    auto id = user_man_->convert_login_to_user_id( r.user_login, false );

    if( id == session_user_id )
        return generic_protocol::create_get_user_id_response( id );

    return generic_protocol::create_error_response( generic_protocol::ErrorResponse::NOT_PERMITTED, "no rights to get user ID of another user" );
}

generic_protocol::BackwardMessage* Handler::handle_GetSessionInfoRequest( session_manager::user_id_t session_user_id, const generic_protocol::ForwardMessage * rr )
{
    auto & r = dynamic_cast< const generic_protocol::GetSessionInfoRequest &>( * rr );

    session_manager::Manager::SessionInfo si;

    if( sess_man_->get_session_info( & si, r.id ) )
    {
        generic_protocol::SessionInfo g_si;

        generic_protocol::init( & g_si, si.user_id, utils::to_epoch( si.start_time ), utils::to_epoch( si.expiration_time ) );

        return generic_protocol::create_GetSessionInfoResponse( g_si );
    }

    return generic_protocol::create_error_response( generic_protocol::ErrorResponse::AUTHENTICATION_ERROR, "invalid session id or session id has already expired" );
}

} // namespace generic_handler
