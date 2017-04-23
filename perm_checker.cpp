/*

Permission checker.

Copyright (C) 2017 Sergey Kolevatov

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

// $Revision: 6711 $ $Date:: 2017-04-21 #$ $Author: serge $

#include "perm_checker.h"               // self

#include <typeindex>                    // std::type_index
#include <unordered_map>

#include "generic_protocol/generic_protocol.h"  // generic_protocol::
#include "session_manager/manager.h"            // session_manager::Manager

#include "utils/dummy_logger.h"      // dummy_log
#include "utils/assert.h"            // ASSERT

#define MODULENAME      "generic_handler::PermChecker"

namespace generic_handler
{

PermChecker::PermChecker():
    sess_man_( nullptr )
{
}

bool PermChecker::init(
        session_manager::Manager            * sess_man )
{
    if( !sess_man )
        return false;

    sess_man_           = sess_man;

    return true;
}


bool PermChecker::is_allowed( const generic_protocol::ForwardMessage * req )
{
    typedef PermChecker Type;

    typedef bool (Type::*PPMF)( const generic_protocol::ForwardMessage * rr );

    static const std::unordered_map<std::type_index, PPMF> funcs =
    {
        { typeid( generic_protocol::AuthenticateRequest ),      & Type::is_allowed_AuthenticateRequest },
        { typeid( generic_protocol::AuthenticateAltRequest ),   & Type::is_allowed_AuthenticateAltRequest },
        { typeid( generic_protocol::CloseSessionRequest ),      & Type::is_allowed_CloseSessionRequest },
        { typeid( generic_protocol::GetUserIdRequest ),         & Type::is_allowed_GetUserIdRequest },
    };

    auto it = funcs.find( typeid( * req ) );

    if( it == funcs.end() )
    {
        dummy_log_fatal( MODULENAME, "is_allowed: cannot cast request to known type - %s", typeid( *req ).name() );

        ASSERT( 0 );

        return nullptr;
    }

    return (this->*it->second)( req );
}

bool PermChecker::is_allowed_AuthenticateRequest( const generic_protocol::ForwardMessage * rr )
{
    return true;
}

bool PermChecker::is_allowed_AuthenticateAltRequest( const generic_protocol::ForwardMessage * rr )
{
    return true;
}

bool PermChecker::is_allowed_CloseSessionRequest( const generic_protocol::ForwardMessage * rr )
{
    return true;
}

bool PermChecker::is_allowed_GetUserIdRequest( const generic_protocol::ForwardMessage * rr )
{
    return true;
}


} // namespace generic_handler
