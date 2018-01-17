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

// $Revision: 8522 $ $Date:: 2018-01-17 #$ $Author: serge $

#ifndef GENERIC_HANDLER_PERM_CHECKER_H
#define GENERIC_HANDLER_PERM_CHECKER_H

namespace generic_protocol
{
class ForwardMessage;
class BackwardMessage;
}

namespace session_manager
{
class Manager;
}

namespace generic_handler
{

class PermChecker
{
public:

    PermChecker();

    bool init(
            session_manager::Manager            * sess_man );

    bool is_allowed( const generic_protocol::ForwardMessage * r );

private:
    bool is_allowed_AuthenticateRequest( const generic_protocol::ForwardMessage * r );
    bool is_allowed_AuthenticateAltRequest( const generic_protocol::ForwardMessage * r );
    bool is_allowed_CloseSessionRequest( const generic_protocol::ForwardMessage * r );
    bool is_allowed_GetUserIdRequest( const generic_protocol::ForwardMessage * r );
    bool is_allowed_GetSessionInfoRequest( const generic_protocol::ForwardMessage * r );

private:
    session_manager::Manager            * sess_man_;

};

} // namespace generic_handler

#endif // GENERIC_HANDLER_PERM_CHECKER_H
