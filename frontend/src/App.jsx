// src/App.jsx
// Root component providing AuthProvider and RouterProvider.

import { RouterProvider } from 'react-router-dom';
import { router } from './router/index';
import { AuthProvider } from './context/AuthContext';

export default function App() {
  return (
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  );
}
