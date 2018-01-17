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

// $Revision: 8527 $ $Date:: 2018-01-17 #$ $Author: serge $

#include "handler.h"                // self

#include <typeindex>                // std::type_index
#include <unordered_map>

#include "utils/mutex_helper.h"      // MUTEX_SCOPE_LOCK
#include "utils/dummy_logger.h"      // dummy_log
#include "utils/assert.h"            // ASSERT
#include "utils/chrono_epoch.h"     // utils::to_epoch

#include "generic_protocol/response_gen.h"              // generic_protocol::create_error_response

#include "session_manager/manager.h" // session_manager::Manager
#include "password_hasher/login_to_id_converter.h"      // password_hasher::convert_login_to_id

#define MODULENAME      "generic_handler::Handler"

namespace generic_handler
{

Handler::Handler():
        sess_man_( nullptr )
{
}

bool Handler::init(
        session_manager::Manager    * sess_man )
{
    MUTEX_SCOPE_LOCK( mutex_ );

    if( !sess_man )
        return false;

    sess_man_   = sess_man;

    return true;
}


generic_protocol::BackwardMessage* Handler::handle( const generic_protocol::ForwardMessage * req )
{
    MUTEX_SCOPE_LOCK( mutex_ );

    typedef Handler Type;

    typedef generic_protocol::BackwardMessage* (Type::*PPMF)( const generic_protocol::ForwardMessage * r );

    static const std::unordered_map<std::type_index, PPMF> funcs =
    {
        { typeid( generic_protocol::AuthenticateRequest ),      & Type::handle_AuthenticateRequest },
        { typeid( generic_protocol::AuthenticateAltRequest ),   & Type::handle_AuthenticateAltRequest },
        { typeid( generic_protocol::CloseSessionRequest ),      & Type::handle_CloseSessionRequest },
        { typeid( generic_protocol::GetUserIdRequest ),         & Type::handle_GetUserIdRequest },
        { typeid( generic_protocol::GetSessionInfoRequest ),    & Type::handle_GetSessionInfoRequest },
    };

    auto it = funcs.find( typeid( * req ) );

    if( it == funcs.end() )
    {
        dummy_log_fatal( MODULENAME, "handle: cannot cast request to known type - %s", typeid( *req ).name() );

        ASSERT( 0 );

        return nullptr;
    }

    return (this->*it->second)( req );
}

generic_protocol::BackwardMessage* Handler::handle_AuthenticateRequest( const generic_protocol::ForwardMessage * rr )
{
    auto & r = dynamic_cast< const generic_protocol::AuthenticateRequest &>( * rr );

    uint32_t id = password_hasher::convert_login_to_id( r.user_login );

    dummy_log_debug( MODULENAME, "handle: AuthenticateRequest: login %s, hash %u", r.user_login.c_str(), id );

    std::string session_id;
    std::string error;

    if( sess_man_->authenticate( id, r.password, session_id, error ) )
    {
        return generic_protocol::create_autheticate_response( session_id );
    }

    return generic_protocol::create_error_response( generic_protocol::ErrorResponse::AUTHENTICATION_ERROR, error );
}

generic_protocol::BackwardMessage* Handler::handle_AuthenticateAltRequest( const generic_protocol::ForwardMessage * rr )
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

generic_protocol::BackwardMessage* Handler::handle_CloseSessionRequest( const generic_protocol::ForwardMessage * rr )
{
    auto & r = dynamic_cast< const generic_protocol::CloseSessionRequest &>( * rr );

    std::string error;

    if( sess_man_->close_session( r.session_id, error ) )
    {
        return generic_protocol::create_close_session_response();
    }

    return generic_protocol::create_error_response( generic_protocol::ErrorResponse::RUNTIME_ERROR, error );
}

generic_protocol::BackwardMessage* Handler::handle_GetUserIdRequest( const generic_protocol::ForwardMessage * rr )
{
    auto & r = dynamic_cast< const generic_protocol::GetUserIdRequest &>( * rr );

    uint32_t id = password_hasher::convert_login_to_id( r.user_login );

    uint32_t auth_id;

    if( sess_man_->get_user_id( & auth_id, r.session_id ) )
    {
        if( id == auth_id )
            return generic_protocol::create_get_user_id_response( id );

        return generic_protocol::create_error_response( generic_protocol::ErrorResponse::NOT_PERMITTED, "no rights to get user ID of another user" );
    }

    return generic_protocol::create_error_response( generic_protocol::ErrorResponse::AUTHENTICATION_ERROR, "invalid session id or session id has already expired" );
}

generic_protocol::BackwardMessage* Handler::handle_GetSessionInfoRequest( const generic_protocol::ForwardMessage * rr )
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
