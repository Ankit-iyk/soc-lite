import api from './client';

export async function getCollectorsApi() {
  const response = await api.get('/collectors');
  return response.data;
}