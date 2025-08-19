import React from 'react';
import { NavLink } from 'react-router-dom';
import { User, Shield, Key, FileText } from 'lucide-react';

const Sidebar = () => {
  const navItems = [
    { to: '/profile', icon: <User className="mr-2 h-4 w-4" />, text: 'Profile' },
    { to: '/security', icon: <Shield className="mr-2 h-4 w-4" />, text: 'Security' },
    { to: '/sessions', icon: <Key className="mr-2 h-4 w-4" />, text: 'Sessions' },
    { to: '/consents', icon: <FileText className="mr-2 h-4 w-4" />, text: 'Consents' },
  ];

  return (
    <aside className="w-64 flex-shrink-0 border-r border-gray-200 bg-gray-50">
      <div className="p-4">
        <h2 className="text-lg font-semibold">Menu</h2>
      </div>
      <nav className="flex flex-col p-4">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center rounded-md px-3 py-2 text-sm font-medium ${
                isActive
                  ? 'bg-gray-200 text-gray-900'
                  : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
              }`
            }
          >
            {item.icon}
            {item.text}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
};

export default Sidebar;
